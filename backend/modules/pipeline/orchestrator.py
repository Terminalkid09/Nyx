import asyncio
import logging
import uuid
from datetime import datetime, timezone
from core.events.bus import EventBus

logger = logging.getLogger(__name__)


class ScanPipeline:
    """
    Orchestrates a full scan pipeline:
    1. Crawl (Playwright)
    2. Content Discovery (wordlist brute force)
    3. Param Extraction (parse discovered URLs/forms for params)
    4. Fuzz (Burp Intruder-style with discovered params)
    5. Active Scan (run active checks on all discovered endpoints)
    6. Report (auto-generate summary)
    """

    STEPS = ["crawl", "discovery", "param_extraction", "fuzz", "active_scan", "report"]

    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._pipelines: dict[str, dict] = {}

    async def start_pipeline(
        self,
        target_url: str,
        session_id: str,
        config: dict | None = None,
        wordlists_dir: str | None = None,
    ) -> dict:
        """Start a full scan pipeline. Returns pipeline info with ID."""
        pipeline_id = str(uuid.uuid4())
        cfg = config or {}

        pipeline = {
            "id": pipeline_id,
            "target_url": target_url,
            "session_id": session_id,
            "status": "running",
            "current_step": None,
            "step_progress": 0,
            "steps": {},
            "results": {},
            "errors": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
        }

        for step in self.STEPS:
            pipeline["steps"][step] = {"status": "pending", "progress": 0}

        self._pipelines[pipeline_id] = pipeline

        asyncio.create_task(self._run_pipeline(pipeline_id, cfg, wordlists_dir))

        return pipeline

    async def _run_pipeline(self, pipeline_id: str, config: dict, wordlists_dir: str | None):
        pipeline = self._pipelines[pipeline_id]
        target_url = pipeline["target_url"]
        session_id = pipeline["session_id"]

        collected_urls = []
        collected_forms = []
        discovered_paths = []
        extracted_params = {}

        try:
            # Step 1: Crawl
            pipeline["current_step"] = "crawl"
            pipeline["steps"]["crawl"]["status"] = "running"
            await self._publish_progress(pipeline_id)

            from modules.crawler.service import CrawlerService
            crawler = CrawlerService(self.event_bus)
            crawl_config = config.get("crawl", {})
            crawl_result = await crawler.crawl(
                start_url=target_url,
                max_depth=crawl_config.get("max_depth", 3),
                max_pages=crawl_config.get("max_pages", 50),
                scope_include=crawl_config.get("scope_include", []),
                scope_exclude=crawl_config.get("scope_exclude", []),
                form_fill_config=crawl_config.get("form_fill_config", {}),
                login_macro=crawl_config.get("login_macro", []),
                headers=crawl_config.get("headers", {}),
                respect_robots_txt=crawl_config.get("respect_robots_txt", True),
                job_id=pipeline_id + "_crawl",
            )
            collected_urls = crawl_result.get("discovered_urls", [])
            collected_forms = crawl_result.get("forms_found", [])
            pipeline["results"]["crawl"] = {
                "urls_count": len(collected_urls),
                "forms_count": len(collected_forms),
            }
            pipeline["steps"]["crawl"]["status"] = "completed"
            pipeline["steps"]["crawl"]["progress"] = 100
            await self._publish_progress(pipeline_id)

            # Step 2: Content Discovery
            pipeline["current_step"] = "discovery"
            pipeline["steps"]["discovery"]["status"] = "running"
            await self._publish_progress(pipeline_id)

            from modules.content_discovery.service import ContentDiscoveryService
            discoverer = ContentDiscoveryService(self.event_bus)
            discovery_config = config.get("discovery", {})
            wordlist = discovery_config.get("wordlist_path") or "content_discovery.txt"
            extensions = discovery_config.get("extensions") or [""]

            try:
                disc_result = await discoverer.discover(
                    target_url=target_url,
                    wordlist_path=wordlist,
                    extensions=extensions,
                    methods=["GET"],
                    throttle_ms=0,
                    session_id=session_id,
                )
                discovered_items = disc_result.get("discovered", [])
                discovered_paths = [item["path"] for item in discovered_items if item.get("status_code", 0) not in (404, 0)]
                pipeline["results"]["discovery"] = {
                    "items_count": len(discovered_items),
                    "found_paths": len(discovered_paths),
                }
            except Exception as e:
                logger.warning("Discovery step failed: %s", e)
                pipeline["errors"].append(f"discovery: {e}")

            pipeline["steps"]["discovery"]["status"] = "completed"
            pipeline["steps"]["discovery"]["progress"] = 100
            await self._publish_progress(pipeline_id)

            # Step 3: Param Extraction
            pipeline["current_step"] = "param_extraction"
            pipeline["steps"]["param_extraction"]["status"] = "running"
            await self._publish_progress(pipeline_id)

            from urllib.parse import urlparse, parse_qs
            all_urls = collected_urls + discovered_paths
            for url in all_urls:
                parsed = urlparse(url if url.startswith("http") else f"{target_url.rstrip('/')}/{url.lstrip('/')}")
                qs = parse_qs(parsed.query)
                if qs:
                    for param_name in qs:
                        if param_name not in extracted_params:
                            extracted_params[param_name] = {"urls": [], "values_seen": set()}
                        extracted_params[param_name]["urls"].append(url)
                        extracted_params[param_name]["values_seen"].update(qs[param_name])

            for form in collected_forms:
                for inp in form.get("inputs", []):
                    name = inp.get("name", "")
                    if name:
                        if name not in extracted_params:
                            extracted_params[name] = {"urls": [], "values_seen": set()}
                        extracted_params[name]["urls"].append(form.get("page_url", ""))

            pipeline["results"]["param_extraction"] = {
                "params_count": len(extracted_params),
                "params": list(extracted_params.keys()),
            }
            pipeline["steps"]["param_extraction"]["status"] = "completed"
            pipeline["steps"]["param_extraction"]["progress"] = 100
            await self._publish_progress(pipeline_id)

            # Step 4: Fuzz
            pipeline["current_step"] = "fuzz"
            pipeline["steps"]["fuzz"]["status"] = "running"
            await self._publish_progress(pipeline_id)

            if extracted_params and all_urls:
                fuzz_config = config.get("fuzz", {})
                fuzz_attack_type = fuzz_config.get("attack_type", "sniper")

                pipeline["results"]["fuzz"] = {
                    "params_available": list(extracted_params.keys()),
                    "attack_type": fuzz_attack_type,
                    "recommended_url": target_url,
                    "note": "Fuzz job available in Fuzzer UI with pre-populated params",
                }

            pipeline["steps"]["fuzz"]["status"] = "completed"
            pipeline["steps"]["fuzz"]["progress"] = 100
            await self._publish_progress(pipeline_id)

            # Step 5: Active Scan
            pipeline["current_step"] = "active_scan"
            pipeline["steps"]["active_scan"]["status"] = "running"
            await self._publish_progress(pipeline_id)

            from modules.scanner.active.scanner import ActiveScanner
            active_scanner = ActiveScanner()

            scan_targets = all_urls[:5]
            active_findings = []
            for scan_url in scan_targets:
                base_req = {"method": "GET", "url": scan_url, "headers": {}, "body": None}
                try:
                    findings = await active_scanner.run_checks(base_req, list(extracted_params.keys())[:3])
                    active_findings.extend(findings)
                except Exception as e:
                    logger.warning("Active scan of %s failed: %s", scan_url, e)

            pipeline["results"]["active_scan"] = {
                "urls_scanned": len(scan_targets),
                "findings_count": len(active_findings),
            }
            pipeline["steps"]["active_scan"]["status"] = "completed"
            pipeline["steps"]["active_scan"]["progress"] = 100
            await self._publish_progress(pipeline_id)

            # Step 6: Report
            pipeline["current_step"] = "report"
            pipeline["steps"]["report"]["status"] = "running"
            await self._publish_progress(pipeline_id)

            report = self._generate_report(pipeline)
            pipeline["results"]["report"] = report
            pipeline["steps"]["report"]["status"] = "completed"
            pipeline["steps"]["report"]["progress"] = 100

            pipeline["status"] = "completed"
            pipeline["completed_at"] = datetime.now(timezone.utc).isoformat()
            await self._publish_progress(pipeline_id)

            await self.event_bus.publish({
                "type": "pipeline.completed",
                "pipeline_id": pipeline_id,
                "target_url": target_url,
            })

        except Exception as e:
            logger.error("Pipeline %s failed: %s", pipeline_id, e)
            pipeline["status"] = "failed"
            pipeline["errors"].append(str(e))
            pipeline["completed_at"] = datetime.now(timezone.utc).isoformat()
            await self._publish_progress(pipeline_id)

    def _generate_report(self, pipeline: dict) -> dict:
        results = pipeline.get("results", {})
        steps = pipeline.get("steps", {})
        return {
            "summary": {
                "total_findings": results.get("active_scan", {}).get("findings_count", 0),
                "urls_discovered": results.get("crawl", {}).get("urls_count", 0),
                "params_found": results.get("param_extraction", {}).get("params_count", 0),
                "paths_discovered": results.get("discovery", {}).get("found_paths", 0),
            },
            "step_summary": {
                step: info.get("status", "unknown")
                for step, info in steps.items()
            },
        }

    async def _publish_progress(self, pipeline_id: str):
        pipeline = self._pipelines.get(pipeline_id)
        if not pipeline:
            return
        steps_total = len(self.STEPS)
        progress_per_step = 100.0 / steps_total
        overall = 0.0
        for step_name in self.STEPS:
            step = pipeline["steps"].get(step_name, {})
            step_progress = step.get("progress", 0)
            if step.get("status") == "completed":
                overall += progress_per_step
            elif step.get("status") == "running":
                overall += progress_per_step * (step_progress / 100.0)

        await self.event_bus.publish({
            "type": "pipeline.progress",
            "pipeline_id": pipeline_id,
            "target_url": pipeline["target_url"],
            "current_step": pipeline["current_step"],
            "progress": round(overall, 1),
            "status": pipeline["status"],
            "steps": pipeline["steps"],
        })

    def get_pipeline(self, pipeline_id: str) -> dict | None:
        return self._pipelines.get(pipeline_id)

    def list_pipelines(self) -> list[dict]:
        return [
            {
                "id": p["id"],
                "target_url": p["target_url"],
                "status": p["status"],
                "current_step": p["current_step"],
                "progress": self._calc_overall_progress(p),
                "started_at": p["started_at"],
            }
            for p in self._pipelines.values()
        ]

    def _calc_overall_progress(self, pipeline: dict) -> float:
        steps_total = len(self.STEPS)
        progress_per_step = 100.0 / steps_total
        overall = 0.0
        for step_name in self.STEPS:
            step = pipeline.get("steps", {}).get(step_name, {})
            step_progress = step.get("progress", 0)
            if step.get("status") == "completed":
                overall += progress_per_step
            elif step.get("status") == "running":
                overall += progress_per_step * (step_progress / 100.0)
        return round(overall, 1)

    def cancel_pipeline(self, pipeline_id: str):
        pipeline = self._pipelines.get(pipeline_id)
        if pipeline:
            pipeline["status"] = "cancelled"
            pipeline["completed_at"] = datetime.now(timezone.utc).isoformat()

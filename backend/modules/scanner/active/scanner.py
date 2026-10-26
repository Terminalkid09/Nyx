import asyncio
import logging
import time
import uuid
from urllib.parse import urlparse
from core.config import settings
from core.events.bus import EventBus
from core.storage.finding_events import persist_results
from modules.scanner.fingerprint import fingerprint_server, select_checks_for_target
from modules.scanner.cvss_mapper import get_cvss_for_cwe
from modules.scanner.active.checks.active_api_key_url import ActiveApiKeyUrlCheck
from modules.scanner.active.checks.active_cert_transparency import ActiveCertTransparencyCheck
from modules.scanner.active.checks.active_cors_null_test import ActiveCorsNullTestCheck
from modules.scanner.active.checks.active_cors_wildcard_test import ActiveCorsWildcardTestCheck
from modules.scanner.active.checks.active_crlf_injection_headers import ActiveCrlfInjectionHeadersCheck
from modules.scanner.active.checks.active_default_admin import ActiveDefaultAdminCheck
from modules.scanner.active.checks.active_default_admin2 import ActiveDefaultAdmin2Check
from modules.scanner.active.checks.active_default_admin3 import ActiveDefaultAdmin3Check
from modules.scanner.active.checks.active_django_debug import ActiveDjangoDebugCheck
from modules.scanner.active.checks.active_el_injection_advanced import ActiveElInjectionAdvancedCheck
from modules.scanner.active.checks.active_express_debug import ActiveExpressDebugCheck
from modules.scanner.active.checks.active_flask_debug import ActiveFlaskDebugCheck
from modules.scanner.active.checks.active_graphql_introspection import ActiveGraphqlIntrospectionCheck
from modules.scanner.active.checks.active_graphql_mutation import ActiveGraphqlMutationCheck
from modules.scanner.active.checks.active_hsts_preload import ActiveHstsPreloadCheck
from modules.scanner.active.checks.active_hsts_subdomain import ActiveHstsSubdomainCheck
from modules.scanner.active.checks.active_laravel_debug import ActiveLaravelDebugCheck
from modules.scanner.active.checks.active_ldap_form_fields import ActiveLdapFormFieldsCheck
from modules.scanner.active.checks.active_nextjs_source import ActiveNextjsSourceCheck
from modules.scanner.active.checks.active_oauth_csrf import ActiveOauthCsrfCheck
from modules.scanner.active.checks.active_oauth_redirect import ActiveOauthRedirectCheck
from modules.scanner.active.checks.active_oauth_scope import ActiveOauthScopeCheck
from modules.scanner.active.checks.active_ocsp_stapling import ActiveOcspStaplingCheck
from modules.scanner.active.checks.active_pfs_missing import ActivePfsMissingCheck
from modules.scanner.active.checks.active_prototype_pollution_json import ActivePrototypePollutionJsonCheck
from modules.scanner.active.checks.active_race_cart_checkout import ActiveRaceCartCheckoutCheck
from modules.scanner.active.checks.active_race_coupon_redemption import ActiveRaceCouponRedemptionCheck
from modules.scanner.active.checks.active_race_duplicate_resource import ActiveRaceDuplicateResourceCheck
from modules.scanner.active.checks.active_race_email_change import ActiveRaceEmailChangeCheck
from modules.scanner.active.checks.active_race_like_manipulation import ActiveRaceLikeManipulationCheck
from modules.scanner.active.checks.active_race_password_change import ActiveRacePasswordChangeCheck
from modules.scanner.active.checks.active_rails_secret import ActiveRailsSecretCheck
from modules.scanner.active.checks.active_rate_limit_bypass import ActiveRateLimitBypassCheck
from modules.scanner.active.checks.active_response_splitting import ActiveResponseSplittingCheck
from modules.scanner.active.checks.active_spel_injection_advanced import ActiveSpelInjectionAdvancedCheck
from modules.scanner.active.checks.active_spring_actuator import ActiveSpringActuatorCheck
from modules.scanner.active.checks.active_sslv3 import ActiveSslv3Check
from modules.scanner.active.checks.active_swagger_exposed import ActiveSwaggerExposedCheck
from modules.scanner.active.checks.active_template_injection_cookies import ActiveTemplateInjectionCookiesCheck
from modules.scanner.active.checks.active_template_injection_headers import ActiveTemplateInjectionHeadersCheck
from modules.scanner.active.checks.active_tls_v10 import ActiveTlsV10Check
from modules.scanner.active.checks.active_tls_v11 import ActiveTlsV11Check
from modules.scanner.active.checks.active_weak_ciphers import ActiveWeakCiphersCheck
from modules.scanner.active.checks.active_wordpress_enum import ActiveWordpressEnumCheck
from modules.scanner.active.checks.active_xcontent_type_options import ActiveXcontentTypeOptionsCheck
from modules.scanner.active.checks.active_xframe_options import ActiveXframeOptionsCheck
from modules.scanner.active.checks.active_xpath_cookies import ActiveXpathCookiesCheck
from modules.scanner.active.checks.active_xpath_headers import ActiveXpathHeadersCheck
from modules.scanner.active.checks.active_xpath_injection_ext import ActiveXpathInjectionExtCheck
from modules.scanner.active.checks.cache_deception import CacheDeceptionCheck
from modules.scanner.active.checks.cache_poisoning import CachePoisoningCheck
from modules.scanner.active.checks.cassandra_injection import CassandraInjectionCheck
from modules.scanner.active.checks.cmd_injection_variants import CmdInjectionVariantsCheck
from modules.scanner.active.checks.content_type_sniff import ContentTypeSniffCheck
from modules.scanner.active.checks.cors_misconfig_active import CorsMisconfigActiveCheck
from modules.scanner.active.checks.cors_wildcard import CorsWildcardCheck
from modules.scanner.active.checks.csrf_active import CsrfActiveCheck
from modules.scanner.active.checks.dotnet_deserialization import DotnetDeserializationCheck
from modules.scanner.active.checks.el_injection import ElInjectionCheck
from modules.scanner.active.checks.host_header_injection import HostHeaderInjectionCheck
from modules.scanner.active.checks.hpp import HppCheck
from modules.scanner.active.checks.http_param_pollution import HttpParamPollutionCheck
from modules.scanner.active.checks.idor import IdorCheck
from modules.scanner.active.checks.java_deserialization import JavaDeserializationCheck
from modules.scanner.active.checks.jwt_none_active import JwtNoneActiveCheck
from modules.scanner.active.checks.ldap_injection_active import LdapInjectionActiveCheck
from modules.scanner.active.checks.lfi import LfiCheck
from modules.scanner.active.checks.memcached_injection import MemcachedInjectionCheck
from modules.scanner.active.checks.method_override import MethodOverrideCheck
from modules.scanner.active.checks.mqtt_injection import MqttInjectionCheck
from modules.scanner.active.checks.nosql_injection_active import NoSqlInjectionActiveCheck
from modules.scanner.active.checks.nosqli import NoSqlInjectionCheck
from modules.scanner.active.checks.oauth_misconfig import OAuthMisconfigCheck
from modules.scanner.active.checks.open_redirect import OpenRedirectCheck as ActiveOpenRedirectCheck
from modules.scanner.active.checks.parameter_pollution import ParameterPollutionCheck
from modules.scanner.active.checks.path_traversal_variants import PathTraversalVariantsCheck
from modules.scanner.active.checks.prototype_pollution import PrototypePollutionCheck
from modules.scanner.active.checks.race_condition import RaceConditionCheck
from modules.scanner.active.checks.redis_injection import RedisInjectionCheck
from modules.scanner.active.checks.request_smuggling import RequestSmugglingCheck
from modules.scanner.active.checks.session_fixation import SessionFixationCheck
from modules.scanner.active.checks.soap_injection import SoapInjectionCheck
from modules.scanner.active.checks.spel_injection import SpelInjectionCheck
from modules.scanner.active.checks.sqli import SQLiCheck
from modules.scanner.active.checks.sqli_variants import SqliVariantsCheck
from modules.scanner.active.checks.ssi_injection import SsiInjectionCheck
from modules.scanner.active.checks.ssrf import SsrfCheck
from modules.scanner.active.checks.ssrf_variants import SsrfVariantsCheck
from modules.scanner.active.checks.ssti import SstiCheck
from modules.scanner.active.checks.ssti_injection import SstiInjectionCheck
from modules.scanner.active.checks.web_cache_poison import WebCachePoisonCheck
from modules.scanner.active.checks.xml_external_entity import XmlExternalEntityCheck
from modules.scanner.active.checks.xpath_injection_active import XPathInjectionActiveCheck
from modules.scanner.active.checks.xslt_injection import XsltInjectionCheck
from modules.scanner.active.checks.xss import XssCheck
from modules.scanner.active.checks.xss_variants import XssVariantsCheck
from modules.scanner.active.checks.xst import XstCheck
from modules.scanner.active.checks.xxe import XxeCheck
from modules.scanner.active.checks.xxe_injection import XxeInjectionCheck

# New checks
from modules.scanner.active.checks.active_aws_keys import ActiveAwsKeysCheck
from modules.scanner.active.checks.active_cors_credentials import ActiveCorsCredentialsCheck
from modules.scanner.active.checks.active_csp_bypass import ActiveCspBypassCheck
from modules.scanner.active.checks.active_dir_listing import ActiveDirListingCheck
from modules.scanner.active.checks.active_dom_xss import ActiveDomXssCheck
from modules.scanner.active.checks.active_elb_check import ActiveElbCheck
from modules.scanner.active.checks.active_email_injection import ActiveEmailInjectionCheck
from modules.scanner.active.checks.active_form_action_override import ActiveFormActionOverrideCheck
from modules.scanner.active.checks.active_git_exposed import ActiveGitExposedCheck
from modules.scanner.active.checks.active_grafana_check import ActiveGrafanaCheck
from modules.scanner.active.checks.active_graphql_batch import ActiveGraphqlBatchCheck
from modules.scanner.active.checks.active_h2c_smuggling import ActiveH2cSmugglingCheck
from modules.scanner.active.checks.active_header_injection import ActiveHeaderInjectionCheck
from modules.scanner.active.checks.active_hsts_missing import ActiveHstsMissingCheck
from modules.scanner.active.checks.active_http_methods import ActiveHttpMethodsCheck
from modules.scanner.active.checks.active_jsource_exposed import ActiveJsourceExposedCheck
from modules.scanner.active.checks.active_jwt_alg_confusion import ActiveJwtAlgConfusionCheck
from modules.scanner.active.checks.active_kibana_check import ActiveKibanaCheck
from modules.scanner.active.checks.active_log4shell import ActiveLog4shellCheck
from modules.scanner.active.checks.active_oast import ActiveOastCheck
from modules.scanner.active.checks.active_open_bucket_check import ActiveOpenBucketCheck
from modules.scanner.active.checks.active_prometheus_check import ActivePrometheusCheck
from modules.scanner.active.checks.active_sqli_blind import ActiveSqliBlindCheck
from modules.scanner.active.checks.active_sqlmap_api import ActiveSqlmapApiCheck
from modules.scanner.active.checks.active_ssti_blind import ActiveSstiBlindCheck
from modules.scanner.active.checks.active_time_blind import ActiveTimeBlindCheck
from modules.scanner.active.checks.active_svg_upload import ActiveSvgUploadCheck
from modules.scanner.active.checks.active_tomcat_manager import ActiveTomcatManagerCheck
from modules.scanner.active.checks.active_traversal_encoded import ActiveTraversalEncodedCheck
from modules.scanner.active.checks.active_verb_tampering import ActiveVerbTamperingCheck
from modules.scanner.active.checks.active_version_enum import ActiveVersionEnumCheck
from modules.scanner.active.checks.active_websocket_origin import ActiveWebsocketOriginCheck
from modules.scanner.active.checks.active_xss_context import ActiveXssContextCheck
from modules.scanner.active.checks.active_xss_dom_based import ActiveXssDomBasedCheck
from modules.scanner.active.checks.auth_checks import (
    ActiveAuthPrivilegeEscalationCheck,
    ActiveAuthIdorCheck,
    ActiveAuthSessionFixationCheck,
    ActiveAuthRoleManipulationCheck,
    ActiveAuthForcedBrowsingCheck,
    ActiveAuthParamTamperingCheck,
)

logger = logging.getLogger(__name__)


def normalize_base_request(base_request: dict) -> dict:
    """Translate the UI/CLI ``body`` key into what httpx understands.

    Checks call ``client.request(**request)``; httpx accepts ``content``, not
    ``body``. Every request-based check was therefore raising TypeError inside
    its ``except Exception: continue``, silently producing zero findings for
    anything that needed a probe. Evidence keeps the original event shape.
    """
    request = dict(base_request)
    body = request.pop("body", None)
    if body is not None and "content" not in request and "data" not in request:
        request["content"] = body
    return request


def remember_finding(result, seen: set) -> bool:
    """Return True the first time a weakness is reported for a parameter.

    Several checks cover the same weakness (error-based and variant XSS, LDAP
    payload families): keying on the title kept every one of them and a single
    reflected parameter produced three findings. The stable identity of a
    finding is (CWE, parameter); the title is only a fallback for checks that
    do not set a CWE. Different parameters stay distinct (BUG-02).
    """
    cwe = str(getattr(result, "cwe", None) or "")
    param = str(getattr(result, "param", None) or "")
    if cwe:
        key = ("cwe", cwe, param)
    else:
        key = ("title", str(getattr(result, "title", None) or ""), param)
    if key in seen:
        return False
    seen.add(key)
    return True


class ActiveScanner:
    def __init__(self, event_bus: EventBus | None = None):
        self.event_bus = event_bus
        self._checks: list | None = None

    @property
    def checks(self):
        if self._checks is None:
            self._checks = self._build_checks()
        return self._checks

    def _build_checks(self) -> list:
        return [
            ActiveApiKeyUrlCheck(),
            ActiveCertTransparencyCheck(),
            ActiveCorsNullTestCheck(),
            ActiveCorsWildcardTestCheck(),
            ActiveCrlfInjectionHeadersCheck(),
            ActiveDefaultAdminCheck(),
            ActiveDefaultAdmin2Check(),
            ActiveDefaultAdmin3Check(),
            ActiveDjangoDebugCheck(),
            ActiveElInjectionAdvancedCheck(),
            ActiveExpressDebugCheck(),
            ActiveFlaskDebugCheck(),
            ActiveGraphqlIntrospectionCheck(),
            ActiveGraphqlMutationCheck(),
            ActiveHstsPreloadCheck(),
            ActiveHstsSubdomainCheck(),
            ActiveLaravelDebugCheck(),
            ActiveLdapFormFieldsCheck(),
            ActiveNextjsSourceCheck(),
            ActiveOauthCsrfCheck(),
            ActiveOauthRedirectCheck(),
            ActiveOauthScopeCheck(),
            ActiveOcspStaplingCheck(),
            ActivePfsMissingCheck(),
            ActivePrototypePollutionJsonCheck(),
            ActiveRaceCartCheckoutCheck(),
            ActiveRaceCouponRedemptionCheck(),
            ActiveRaceDuplicateResourceCheck(),
            ActiveRaceEmailChangeCheck(),
            ActiveRaceLikeManipulationCheck(),
            ActiveRacePasswordChangeCheck(),
            ActiveRailsSecretCheck(),
            ActiveRateLimitBypassCheck(),
            ActiveResponseSplittingCheck(),
            ActiveSpelInjectionAdvancedCheck(),
            ActiveSpringActuatorCheck(),
            ActiveSslv3Check(),
            ActiveSwaggerExposedCheck(),
            ActiveTemplateInjectionCookiesCheck(),
            ActiveTemplateInjectionHeadersCheck(),
            ActiveTlsV10Check(),
            ActiveTlsV11Check(),
            ActiveWeakCiphersCheck(),
            ActiveWordpressEnumCheck(),
            ActiveXcontentTypeOptionsCheck(),
            ActiveXframeOptionsCheck(),
            ActiveXpathCookiesCheck(),
            ActiveXpathHeadersCheck(),
            ActiveXpathInjectionExtCheck(),
            CacheDeceptionCheck(),
            CachePoisoningCheck(),
            CassandraInjectionCheck(),
            CmdInjectionVariantsCheck(),
            ContentTypeSniffCheck(),
            CorsMisconfigActiveCheck(),
            CorsWildcardCheck(),
            CsrfActiveCheck(),
            DotnetDeserializationCheck(),
            ElInjectionCheck(),
            HostHeaderInjectionCheck(),
            HppCheck(),
            HttpParamPollutionCheck(),
            IdorCheck(),
            JavaDeserializationCheck(),
            JwtNoneActiveCheck(),
            LdapInjectionActiveCheck(),
            LfiCheck(),
            MemcachedInjectionCheck(),
            MethodOverrideCheck(),
            MqttInjectionCheck(),
            NoSqlInjectionActiveCheck(),
            OAuthMisconfigCheck(),
            ActiveOpenRedirectCheck(),
            ParameterPollutionCheck(),
            PathTraversalVariantsCheck(),
            PrototypePollutionCheck(),
            RaceConditionCheck(),
            RedisInjectionCheck(),
            RequestSmugglingCheck(),
            SessionFixationCheck(),
            SoapInjectionCheck(),
            SpelInjectionCheck(),
            SQLiCheck(),
            SqliVariantsCheck(),
            SsiInjectionCheck(),
            SsrfCheck(),
            SsrfVariantsCheck(),
            SstiCheck(),
            SstiInjectionCheck(),
            WebCachePoisonCheck(),
            XmlExternalEntityCheck(),
            XPathInjectionActiveCheck(),
            XsltInjectionCheck(),
            XssCheck(),
            XssVariantsCheck(),
            XstCheck(),
            XxeCheck(),
            XxeInjectionCheck(),
            # New checks
            ActiveAwsKeysCheck(),
            ActiveCorsCredentialsCheck(),
            ActiveCspBypassCheck(),
            ActiveDirListingCheck(),
            ActiveDomXssCheck(),
            ActiveElbCheck(),
            ActiveEmailInjectionCheck(),
            ActiveFormActionOverrideCheck(),
            ActiveGitExposedCheck(),
            ActiveGrafanaCheck(),
            ActiveGraphqlBatchCheck(),
            ActiveH2cSmugglingCheck(),
            ActiveHeaderInjectionCheck(),
            ActiveHstsMissingCheck(),
            ActiveHttpMethodsCheck(),
            ActiveJsourceExposedCheck(),
            ActiveJwtAlgConfusionCheck(),
            ActiveKibanaCheck(),
            ActiveLog4shellCheck(),
            ActiveOastCheck(),
            ActiveOpenBucketCheck(),
            ActivePrometheusCheck(),
            ActiveSqliBlindCheck(),
            ActiveSqlmapApiCheck(),
            ActiveSstiBlindCheck(),
            ActiveTimeBlindCheck(),
            ActiveSvgUploadCheck(),
            ActiveTomcatManagerCheck(),
            ActiveTraversalEncodedCheck(),
            ActiveVerbTamperingCheck(),
            ActiveVersionEnumCheck(),
            ActiveWebsocketOriginCheck(),
            ActiveXssContextCheck(),
            ActiveXssDomBasedCheck(),
            # Auth-specific checks
            ActiveAuthPrivilegeEscalationCheck(),
            ActiveAuthIdorCheck(),
            ActiveAuthSessionFixationCheck(),
            ActiveAuthRoleManipulationCheck(),
            ActiveAuthForcedBrowsingCheck(),
            ActiveAuthParamTamperingCheck(),
        ]

    async def fingerprint(self, target_url: str) -> dict:
        return await fingerprint_server(target_url)

    async def discover_params(self, target_url: str, concurrency: int = 5, session_id: str | None = None) -> list[dict]:
        try:
            from modules.automations.param_chain import ParamDiscoveryService
            service = ParamDiscoveryService(self.event_bus or EventBus())
            result = await service.discover(target_url, concurrency, session_id=session_id)
            return result.get("discovered_params", [])
        except Exception as e:
            logger.error("Param discovery failed for %s: %s", target_url, e)
            return []

    async def run_checks(
        self,
        base_request: dict,
        target_params: list[str],
        event: dict | None = None,
        fingerprint_info: dict | None = None,
        checks_filter: list[str] | None = None,
        depth: str | None = None,
        deadline_seconds: float | None = None,
    ) -> list[dict]:
        """Run the selected checks against one request.

        Checks execute concurrently behind a semaphore (they are independent
        and network-bound), but results are processed in registration order so
        deduplication and persisted findings stay deterministic. A wall-clock
        deadline returns the checks that finished instead of cancelling the
        whole scan.
        """
        from modules.scanner.scan_depth import get_depth
        from modules.scanner.base_check import (
            reset_payload_budget,
            set_payload_budget,
        )

        depth_profile = get_depth(depth)

        all_results: list[dict] = []
        checks_to_run = list(self.checks)

        if checks_filter:
            checks_to_run = [
                c for c in checks_to_run
                if c.name in checks_filter or any(f in c.name for f in checks_filter)
            ]

        # Depth-based filtering: fast profile skips heavy checks (blind/time/OAST)
        checks_to_run = [
            c for c in checks_to_run if not depth_profile.skip_check(c.name)
        ]

        if fingerprint_info:
            selection = select_checks_for_target(fingerprint_info)
            prioritize_names = selection.get("prioritize", [])
            skip_names = selection.get("skip", [])
            if skip_names:
                # A detected WAF already told us these probes will be blocked
                # or answered by the WAF itself. Requesting them anyway burns
                # the rate budget and produces WAF findings, not target ones.
                checks_to_run = [
                    c for c in checks_to_run
                    if not any(name in c.name for name in skip_names)
                ]
            if prioritize_names:
                prioritized = [c for c in checks_to_run if c.name in prioritize_names]
                rest = [c for c in checks_to_run if c.name not in prioritize_names]
                checks_to_run = prioritized + rest

        # Depth-based budget: the profile caps BOTH how many parameters a check
        # sees and how many payloads it sends per parameter.
        max_payloads = depth_profile.max_payloads_per_param
        params_for_scan = target_params
        if len(target_params) > max_payloads:
            params_for_scan = target_params[:max_payloads]

        # Scope is a hard barrier, not a UI filter: resolve the session that
        # produced this request and refuse to probe URLs it did not authorize.
        # No rules configured means "allow", matching check_scope().
        raw_session_id = event.get("session_id") if event else None
        session_id = None
        if raw_session_id:
            try:
                session_id = uuid.UUID(str(raw_session_id))
            except (TypeError, ValueError):
                session_id = None
        if settings.SCAN_ENFORCE_SCOPE:
            from core.authorization import authorize
            # Pass the raw value: authorize() fails closed on malformed ids
            # instead of degrading to an unscoped scan.
            allowed, kind, detail = await authorize(
                raw_session_id, base_request.get("url", "")
            )
            if not allowed:
                logger.info(
                    "Active scan refused: %s (%s: %s)",
                    base_request.get("url", ""), kind, detail,
                )
                if self.event_bus:
                    await self.event_bus.publish({
                        "type": "scan.skipped",
                        "url": base_request.get("url", ""),
                        "session_id": str(session_id) if session_id else None,
                        "reason": kind,
                        "rule": detail,
                    })
                return []

        request_for_checks = normalize_base_request(base_request)

        seen_findings: set = set()
        started = time.monotonic()
        deadline = started + deadline_seconds if deadline_seconds else None
        semaphore = asyncio.Semaphore(max(1, int(settings.SCAN_MAX_CONCURRENCY)))
        budget_reported = False
        target_url = base_request.get("url", "")

        async def run_one(check):
            nonlocal budget_reported
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                if self.event_bus and not budget_reported:
                    budget_reported = True
                    await self.event_bus.publish({
                        "type": "scan.budget_exhausted",
                        "url": target_url,
                        "session_id": str(session_id) if session_id else None,
                    })
                return check, None

            async with semaphore:
                # Re-check authorization for every check: a long scan can run
                # past its RoE window, and a profile can be deactivated while
                # the scan is in flight. The initial gate alone is not enough.
                if settings.SCAN_ENFORCE_SCOPE:
                    from core.authorization import authorize
                    allowed, kind, detail = await authorize(
                        raw_session_id, target_url
                    )
                    if not allowed:
                        logger.info(
                            "Active check %s refused (%s: %s)",
                            check.name, kind, detail,
                        )
                        if self.event_bus:
                            await self.event_bus.publish({
                                "type": "scan.skipped",
                                "url": target_url,
                                "check": check.name,
                                "session_id": str(session_id) if session_id else None,
                                "reason": kind,
                                "rule": detail,
                            })
                        return check, None

                # RoE pacing is enforced per probe, not once per engagement:
                # a signed max_rps is a ceiling on what actually leaves the box.
                try:
                    from core.roe import pace
                    await pace(target_url)
                except Exception:
                    logger.debug("RoE pacing lookup failed", exc_info=True)

                timeout = settings.SCAN_CHECK_TIMEOUT_SECONDS
                if remaining is not None:
                    timeout = min(timeout, max(0.01, remaining))
                try:
                    results = await asyncio.wait_for(
                        check.run(request_for_checks, params_for_scan),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Check %s timed out after %.0fs on %s",
                        check.name, timeout, target_url,
                    )
                    if self.event_bus:
                        await self.event_bus.publish({
                            "type": "scan.check_timeout",
                            "check": check.name,
                            "url": target_url,
                            "session_id": str(session_id) if session_id else None,
                        })
                    return check, []
                except Exception as e:
                    logger.error("Active check %s failed: %s", check.name, e)
                    return check, []
            return check, results

        token = set_payload_budget(max_payloads)
        try:
            completed = await asyncio.gather(*(run_one(c) for c in checks_to_run))
        finally:
            reset_payload_budget(token)

        for check, results in completed:
            if not results:
                continue

            # Apply CVSS and deduplicate in registration order.
            unique_results = []
            for r in results:
                if not r.triggered:
                    continue
                if not remember_finding(r, seen_findings):
                    continue
                cvss_info = get_cvss_for_cwe(r.cwe) if r.cwe else None
                if cvss_info:
                    r.cvss_score = cvss_info["score"]
                    r.cvss_vector = cvss_info["vector"]
                    if not hasattr(r, "severity") or r.severity == "info":
                        r.severity = cvss_info["severity"]
                unique_results.append(r)

            if unique_results and self.event_bus:
                await persist_results(
                    self.event_bus, unique_results, event or base_request,
                    check.name, source="active",
                )

            for r in unique_results:
                all_results.append({
                    "check": check.name,
                    "severity": r.severity,
                    "title": r.title,
                    "description": r.description,
                    "evidence": r.evidence,
                    "remediation": r.remediation,
                    "cwe": r.cwe,
                    "cvss_score": getattr(r, "cvss_score", None),
                    "cvss_vector": getattr(r, "cvss_vector", None),
                })
                logger.info(
                    "Active check %s: %s (CVSS: %s)",
                    check.name, r.title, getattr(r, "cvss_score", "N/A"),
                )
        return all_results

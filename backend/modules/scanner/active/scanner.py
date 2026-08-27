import logging
from urllib.parse import urlparse
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
from modules.scanner.active.checks.active_ldap_injection import ActiveLdapInjectionCheck
from modules.scanner.active.checks.active_memcached_injection import ActiveMemcachedInjectionCheck
from modules.scanner.active.checks.active_nextjs_source import ActiveNextjsSourceCheck
from modules.scanner.active.checks.active_nosql_injection import ActiveNosqlInjectionCheck
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
from modules.scanner.active.checks.active_redis_injection import ActiveRedisInjectionCheck
from modules.scanner.active.checks.active_response_splitting import ActiveResponseSplittingCheck
from modules.scanner.active.checks.active_soap_injection import ActiveSoapInjectionCheck
from modules.scanner.active.checks.active_spel_injection_advanced import ActiveSpelInjectionAdvancedCheck
from modules.scanner.active.checks.active_spring_actuator import ActiveSpringActuatorCheck
from modules.scanner.active.checks.active_ssi_injection import ActiveSsiInjectionCheck
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
from modules.scanner.active.checks.active_xslt_injection import ActiveXsltInjectionCheck
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
from modules.scanner.active.checks.ldap_injection import LdapInjectionCheck
from modules.scanner.active.checks.ldap_injection_active import LdapInjectionActiveCheck
from modules.scanner.active.checks.lfi import LfiCheck
from modules.scanner.active.checks.memcached_injection import MemcachedInjectionCheck
from modules.scanner.active.checks.method_override import MethodOverrideCheck
from modules.scanner.active.checks.mqtt_injection import MqttInjectionCheck
from modules.scanner.active.checks.nosql_injection import NosqlInjectionCheck
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
from modules.scanner.active.checks.xpath_injection import XPathInjectionCheck
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
            ActiveLdapInjectionCheck(),
            ActiveMemcachedInjectionCheck(),
            ActiveNextjsSourceCheck(),
            ActiveNosqlInjectionCheck(),
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
            ActiveRedisInjectionCheck(),
            ActiveResponseSplittingCheck(),
            ActiveSoapInjectionCheck(),
            ActiveSpelInjectionAdvancedCheck(),
            ActiveSpringActuatorCheck(),
            ActiveSsiInjectionCheck(),
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
            ActiveXsltInjectionCheck(),
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
            LdapInjectionCheck(),
            LdapInjectionActiveCheck(),
            LfiCheck(),
            MemcachedInjectionCheck(),
            MethodOverrideCheck(),
            MqttInjectionCheck(),
            NosqlInjectionCheck(),
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
            XPathInjectionCheck(),
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

    async def discover_params(self, target_url: str, concurrency: int = 5) -> list[dict]:
        try:
            from modules.automations.param_chain import ParamDiscoveryService
            service = ParamDiscoveryService(self.event_bus or EventBus())
            result = await service.discover(target_url, concurrency)
            return result.get("discovered_params", [])
        except Exception as e:
            logger.error("Param discovery failed for %s: %s", target_url, e)
            return []

    async def run_checks(self, base_request: dict, target_params: list[str], event: dict | None = None, fingerprint_info: dict | None = None, checks_filter: list[str] | None = None, depth: str | None = None) -> list[dict]:
        from modules.scanner.scan_depth import get_depth
        depth_profile = get_depth(depth)

        all_results = []
        checks_to_run = self.checks

        if checks_filter:
            checks_to_run = [c for c in checks_to_run if c.name in checks_filter or any(f in c.name for f in checks_filter)]

        # Depth-based filtering: fast profile skips heavy checks (blind/time/OAST)
        if depth_profile.skip_check:
            checks_to_run = [c for c in checks_to_run if not depth_profile.skip_check(c.name)]

        if fingerprint_info:
            selection = select_checks_for_target(fingerprint_info)
            prioritize_names = selection.get("prioritize", [])
            if prioritize_names:
                prioritized = [c for c in checks_to_run if c.name in prioritize_names]
                rest = [c for c in checks_to_run if c.name not in prioritize_names]
                checks_to_run = prioritized + rest

        # Depth-based payload capping: heavy checks get a reduced parameter set
        # in fast/balanced profiles to bound the total request count.
        max_payloads = depth_profile.max_payloads_per_param

        seen_findings = set()
        
        for check in checks_to_run:
            try:
                # Cap parameters for heavy (slow/blind/OAST) checks
                check_is_heavy = any(p in check.name for p in (
                    "time_blind", "sqli_blind", "oast", "race", "log4shell",
                ))
                params_for_check = target_params
                if check_is_heavy and len(target_params) > max_payloads:
                    params_for_check = target_params[:max_payloads]

                results = await check.run(base_request, params_for_check)
                
                # Apply CVSS and Deduplication
                unique_results = []
                for r in results:
                    if r.triggered:
                        # Deduplication key: CWE + Title + Param
                        # This avoids the same check firing multiple times for slightly different payloads on the same parameter
                        dedup_key = f"{r.cwe}_{r.title}"
                        if dedup_key in seen_findings:
                            continue
                        seen_findings.add(dedup_key)
                        
                        # Add CVSS data
                        cvss_info = get_cvss_for_cwe(r.cwe) if r.cwe else None
                        if cvss_info:
                            r.cvss_score = cvss_info["score"]
                            r.cvss_vector = cvss_info["vector"]
                            if not hasattr(r, 'severity') or r.severity == "info":
                                r.severity = cvss_info["severity"]
                        
                        unique_results.append(r)
                
                if unique_results and self.event_bus:
                    await persist_results(self.event_bus, unique_results, event or base_request, check.name, source="active")
                    
                for r in unique_results:
                    all_results.append({
                        "check": check.name,
                        "severity": r.severity,
                        "title": r.title,
                        "description": r.description,
                        "evidence": r.evidence,
                        "remediation": r.remediation,
                        "cwe": r.cwe,
                        "cvss_score": getattr(r, 'cvss_score', None),
                        "cvss_vector": getattr(r, 'cvss_vector', None),
                    })
                    logger.info("Active check %s: %s (CVSS: %s)", check.name, r.title, getattr(r, 'cvss_score', 'N/A'))
            except Exception as e:
                logger.error("Active check %s failed: %s", check.name, e)
        return all_results

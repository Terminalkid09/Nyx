import logging
from core.events.bus import EventBus
from modules.scanner.base_check import BaseCheck
from core.storage.finding_events import persist_results
from modules.scanner.cvss_mapper import get_cvss_for_cwe
from modules.scanner.passive.checks.alapca import AlapcaCheck
from modules.scanner.passive.checks.auth_account_lockout import AuthAccountLockoutCheck
from modules.scanner.passive.checks.auth_default_creds import AuthDefaultCredsCheck
from modules.scanner.passive.checks.auth_login_over_http import AuthLoginOverHttpCheck
from modules.scanner.passive.checks.auth_logout_invalidation import AuthLogoutInvalidationCheck
from modules.scanner.passive.checks.auth_password_autocomplete import AuthPasswordAutocompleteCheck
from modules.scanner.passive.checks.auth_remember_me import AuthRememberMeCheck
from modules.scanner.passive.checks.auth_session_rotation import AuthSessionRotationCheck
from modules.scanner.passive.checks.auth_session_url import AuthSessionUrlCheck
from modules.scanner.passive.checks.auth_verbose_errors import AuthVerboseErrorsCheck
from modules.scanner.passive.checks.auth_weak_password_policy import AuthWeakPasswordPolicyCheck
from modules.scanner.passive.checks.biz_2fa_bypass import Biz2faBypassCheck
from modules.scanner.passive.checks.biz_captcha_direct import BizCaptchaDirectCheck
from modules.scanner.passive.checks.biz_captcha_response import BizCaptchaResponseCheck
from modules.scanner.passive.checks.biz_integer_overflow import BizIntegerOverflowCheck
from modules.scanner.passive.checks.biz_negative_value import BizNegativeValueCheck
from modules.scanner.passive.checks.biz_otp_bypass import BizOtpBypassCheck
from modules.scanner.passive.checks.biz_price_manipulation import BizPriceManipulationCheck
from modules.scanner.passive.checks.biz_quantity import BizQuantityCheck
from modules.scanner.passive.checks.biz_skip_step import BizSkipStepCheck
from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
from modules.scanner.passive.checks.passive_tech_fingerprint import PassiveTechFingerprintCheck
from modules.scanner.passive.checks.biz_unlimited_upload import BizUnlimitedUploadCheck
from modules.scanner.passive.checks.cache_deception_ct import CacheDeceptionCtCheck
from modules.scanner.passive.checks.cache_host_header import CacheHostHeaderCheck
from modules.scanner.passive.checks.cache_key_injection import CacheKeyInjectionCheck
from modules.scanner.passive.checks.cache_poisoning import CachePoisoningCheck
from modules.scanner.passive.checks.cache_private_data import CachePrivateDataCheck
from modules.scanner.passive.checks.cache_static_dynamic import CacheStaticDynamicCheck
from modules.scanner.passive.checks.cache_unkeyed_header import CacheUnkeyedHeaderCheck
from modules.scanner.passive.checks.cache_unkeyed_query import CacheUnkeyedQueryCheck
from modules.scanner.passive.checks.cache_xfh import CacheXfhCheck
from modules.scanner.passive.checks.cdn_misconfig import CdnMisconfigCheck
from modules.scanner.passive.checks.cdn_origin_ip import CdnOriginIpCheck
from modules.scanner.passive.checks.clickjacking import ClickjackingCheck
from modules.scanner.passive.checks.cmd_injection_more import CmdInjectionMoreCheck
from modules.scanner.passive.checks.cookie_attributes import CookieAttributesCheck
from modules.scanner.passive.checks.cookie_flags import CookieFlagsCheck
from modules.scanner.passive.checks.cors_credentials_all import CorsCredentialsAllCheck
from modules.scanner.passive.checks.cors_exposed_headers import CorsExposedHeadersCheck
from modules.scanner.passive.checks.cors_max_age_long import CorsMaxAgeLongCheck
from modules.scanner.passive.checks.cors_misconfig import CorsMisconfigCheck
from modules.scanner.passive.checks.cors_null_origin import CorsNullOriginCheck
from modules.scanner.passive.checks.cors_origin_reflection import CorsOriginReflectionCheck
from modules.scanner.passive.checks.cors_preflight_bypass import CorsPreflightBypassCheck
from modules.scanner.passive.checks.cors_vary_header import CorsVaryHeaderCheck
from modules.scanner.passive.checks.cors_wildcard_creds import CorsWildcardCredsCheck
from modules.scanner.passive.checks.csp_bypass import CspBypassCheck
from modules.scanner.passive.checks.csp_eval import CspEvalCheck
from modules.scanner.passive.checks.csrf_tokens import CsrfTokenCheck
from modules.scanner.passive.checks.directory_listing import DirectoryListingCheck
from modules.scanner.passive.checks.dom_clobbering import DomClobberingCheck
from modules.scanner.passive.checks.dotnet_deserialization import DotnetDeserializationCheck
from modules.scanner.passive.checks.el_injection import ElInjectionCheck
from modules.scanner.passive.checks.elma_injection import ElmaInjectionCheck
from modules.scanner.passive.checks.email_disclosure import EmailDisclosureCheck
from modules.scanner.passive.checks.file_upload_misconfig import FileUploadMisconfigCheck
from modules.scanner.passive.checks.file_upload_more import FileUploadMoreCheck
from modules.scanner.passive.checks.graphql_aliases import GraphqlAliasesCheck
from modules.scanner.passive.checks.graphql_batching import GraphqlBatchingCheck
from modules.scanner.passive.checks.graphql_csrf import GraphqlCsrfCheck
from modules.scanner.passive.checks.graphql_debug import GraphqlDebugCheck
from modules.scanner.passive.checks.graphql_depth import GraphqlDepthCheck
from modules.scanner.passive.checks.graphql_field_suggestions import GraphqlFieldSuggestionsCheck
from modules.scanner.passive.checks.graphql_introspection import GraphQLIntrospectionCheck
from modules.scanner.passive.checks.graphql_no_auth import GraphqlNoAuthCheck
from modules.scanner.passive.checks.hsts_check import HstsCheck
from modules.scanner.passive.checks.http2_downgrade import Http2DowngradeCheck
from modules.scanner.passive.checks.http_methods import HttpMethodsCheck
from modules.scanner.passive.checks.http_param_pollution import HttpParamPollutionCheck
from modules.scanner.passive.checks.info_debug_endpoints import InfoDebugEndpointsCheck
from modules.scanner.passive.checks.info_directory_listing2 import InfoDirectoryListing2Check
from modules.scanner.passive.checks.info_env_file import InfoEnvFileCheck
from modules.scanner.passive.checks.info_git_config import InfoGitConfigCheck
from modules.scanner.passive.checks.info_internal_ip import InfoInternalIpCheck
from modules.scanner.passive.checks.info_leakage import InfoLeakageCheck
from modules.scanner.passive.checks.info_phpinfo import InfoPhpinfoCheck
from modules.scanner.passive.checks.info_server_status import InfoServerStatusCheck
from modules.scanner.passive.checks.info_stack_trace import InfoStackTraceCheck
from modules.scanner.passive.checks.insecure_cookies import InsecureCookiesCheck
from modules.scanner.passive.checks.java_deserialization import JavaDeserializationCheck
from modules.scanner.passive.checks.js_clobbering import JsClobberingCheck
from modules.scanner.passive.checks.jwt_alg_none import JwtAlgNoneCheck
from modules.scanner.passive.checks.jwt_crit_bypass import JwtCritBypassCheck
from modules.scanner.passive.checks.jwt_expired_token import JwtExpiredTokenCheck
from modules.scanner.passive.checks.jwt_exposure import JwtExposureCheck
from modules.scanner.passive.checks.jwt_jku_bypass import JwtJkuBypassCheck
from modules.scanner.passive.checks.jwt_jwk_injection import JwtJwkInjectionCheck
from modules.scanner.passive.checks.jwt_kid_injection import JwtKidInjectionCheck
from modules.scanner.passive.checks.jwt_none_alg import JwtNoneAlgCheck
from modules.scanner.passive.checks.jwt_typ_manipulation import JwtTypManipulationCheck
from modules.scanner.passive.checks.jwt_weak_secret import JwtWeakSecretCheck
from modules.scanner.passive.checks.ldap_more import LdapMoreCheck
from modules.scanner.passive.checks.method_override import MethodOverrideCheck
from modules.scanner.passive.checks.misc_connect_method import MiscConnectMethodCheck
from modules.scanner.passive.checks.misc_crlf_log import MiscCrlfLogCheck
from modules.scanner.passive.checks.misc_csv_injection import MiscCsvInjectionCheck
from modules.scanner.passive.checks.misc_delete_method import MiscDeleteMethodCheck
from modules.scanner.passive.checks.misc_head_enabled import MiscHeadEnabledCheck
from modules.scanner.passive.checks.misc_host_header_password_reset import MiscHostHeaderPasswordResetCheck
from modules.scanner.passive.checks.misc_http09 import MiscHttp09Check
from modules.scanner.passive.checks.misc_mass_assignment import MiscMassAssignmentCheck
from modules.scanner.passive.checks.misc_options_method import MiscOptionsMethodCheck
from modules.scanner.passive.checks.misc_patch_method import MiscPatchMethodCheck
from modules.scanner.passive.checks.misc_put_method import MiscPutMethodCheck
from modules.scanner.passive.checks.misc_reset_token_email import MiscResetTokenEmailCheck
from modules.scanner.passive.checks.misc_response_splitting import MiscResponseSplittingCheck
from modules.scanner.passive.checks.misc_trace_method import MiscTraceMethodCheck
from modules.scanner.passive.checks.misc_url_redirector import MiscUrlRedirectorCheck
from modules.scanner.passive.checks.misc_weak_reset_token import MiscWeakResetTokenCheck
from modules.scanner.passive.checks.missing_headers import MissingHeadersCheck
from modules.scanner.passive.checks.nosql_more import NosqlMoreCheck
from modules.scanner.passive.checks.open_bucket import OpenBucketCheck
from modules.scanner.passive.checks.open_redirect import OpenRedirectCheck
from modules.scanner.passive.checks.open_redirect_passive import OpenRedirectPassiveCheck
from modules.scanner.passive.checks.openapi_exposure import OpenApiExposureCheck
from modules.scanner.passive.checks.path_traversal_more import PathTraversalMoreCheck
from modules.scanner.passive.checks.path_traversal_passive import PathTraversalPassiveCheck
from modules.scanner.passive.checks.postmessage_origin_validation import PostmessageOriginValidationCheck
from modules.scanner.passive.checks.prototype_pollution_client import PrototypePollutionClientCheck
from modules.scanner.passive.checks.prototype_pollution_server import PrototypePollutionServerCheck
from modules.scanner.passive.checks.race_coupon import RaceCouponCheck
from modules.scanner.passive.checks.race_email_verify import RaceEmailVerifyCheck
from modules.scanner.passive.checks.race_file_upload import RaceFileUploadCheck
from modules.scanner.passive.checks.race_payment import RacePaymentCheck
from modules.scanner.passive.checks.race_rate_limit import RaceRateLimitCheck
from modules.scanner.passive.checks.rate_limiting import RateLimitingCheck
from modules.scanner.passive.checks.security_txt import SecurityTxtCheck
from modules.scanner.passive.checks.sensitive_data_exposure import SensitiveDataExposureCheck
from modules.scanner.passive.checks.server_side_includes import ServerSideIncludesCheck
from modules.scanner.passive.checks.smtp_injection import SmtpInjectionCheck
from modules.scanner.passive.checks.smuggling_chunked_parsing import SmugglingChunkedParsingCheck
from modules.scanner.passive.checks.smuggling_cl_cl import SmugglingClClCheck
from modules.scanner.passive.checks.smuggling_cl_te import SmugglingClTeCheck
from modules.scanner.passive.checks.smuggling_content_length import SmugglingContentLengthCheck
from modules.scanner.passive.checks.smuggling_h2_downgrade import SmugglingH2DowngradeCheck
from modules.scanner.passive.checks.smuggling_h2_smuggling import SmugglingH2SmugglingCheck
from modules.scanner.passive.checks.smuggling_te_cl import SmugglingTeClCheck
from modules.scanner.passive.checks.smuggling_te_te import SmugglingTeTeCheck
from modules.scanner.passive.checks.sop_bypass import SopBypassCheck
from modules.scanner.passive.checks.sop_document_domain import SopDocumentDomainCheck
from modules.scanner.passive.checks.sop_window_open import SopWindowOpenCheck
from modules.scanner.passive.checks.spel_injection import SpelInjectionCheck
from modules.scanner.passive.checks.sqli_boolean import SqliBooleanCheck
from modules.scanner.passive.checks.sqli_boolean_indicators import SqliBooleanIndicatorsCheck
from modules.scanner.passive.checks.sqli_cookie_reflection import SqliCookieReflectionCheck
from modules.scanner.passive.checks.sqli_error_mssql import SqliErrorMssqlCheck
from modules.scanner.passive.checks.sqli_error_mysql import SqliErrorMysqlCheck
from modules.scanner.passive.checks.sqli_error_oracle import SqliErrorOracleCheck
from modules.scanner.passive.checks.sqli_error_postgresql import SqliErrorPostgresqlCheck
from modules.scanner.passive.checks.sqli_http_header import SqliHttpHeaderCheck
from modules.scanner.passive.checks.sqli_json_response import SqliJsonResponseCheck
from modules.scanner.passive.checks.sqli_more_variants import SqliMoreVariantsCheck
from modules.scanner.passive.checks.sqli_stacked_mssql import SqliStackedMssqlCheck
from modules.scanner.passive.checks.sqli_stacked_postgresql import SqliStackedPostgresqlCheck
from modules.scanner.passive.checks.sqli_time_indicators import SqliTimeIndicatorsCheck
from modules.scanner.passive.checks.sqli_time_mssql import SqliTimeMssqlCheck
from modules.scanner.passive.checks.sqli_time_mysql import SqliTimeMysqlCheck
from modules.scanner.passive.checks.sqli_time_postgresql import SqliTimePostgresqlCheck
from modules.scanner.passive.checks.sqli_xml_response import SqliXmlResponseCheck
from modules.scanner.passive.checks.ssl_issues import SslIssuesCheck
from modules.scanner.passive.checks.ssrf_more import SsrfMoreCheck
from modules.scanner.passive.checks.ssti_detection import SstiDetectionCheck
from modules.scanner.passive.checks.ssti_erb import SstiErbCheck
from modules.scanner.passive.checks.ssti_freemarker import SstiFreemarkerCheck
from modules.scanner.passive.checks.ssti_handlebars import SstiHandlebarsCheck
from modules.scanner.passive.checks.ssti_jade import SstiJadeCheck
from modules.scanner.passive.checks.ssti_jinja2 import SstiJinja2Check
from modules.scanner.passive.checks.ssti_mako import SstiMakoCheck
from modules.scanner.passive.checks.ssti_mustache import SstiMustacheCheck
from modules.scanner.passive.checks.ssti_smarty import SstiSmartyCheck
from modules.scanner.passive.checks.ssti_tornado import SstiTornadoCheck
from modules.scanner.passive.checks.ssti_twig import SstiTwigCheck
from modules.scanner.passive.checks.ssti_velocity import SstiVelocityCheck
from modules.scanner.passive.checks.subdomain_takeover import SubdomainTakeoverCheck
from modules.scanner.passive.checks.timing_headers import TimingHeadersCheck
from modules.scanner.passive.checks.web_cache_poisoning import WebCachePoisoningCheck
from modules.scanner.passive.checks.ws_cross_origin import WsCrossOriginCheck
from modules.scanner.passive.checks.ws_message_injection import WsMessageInjectionCheck
from modules.scanner.passive.checks.ws_no_auth import WsNoAuthCheck
from modules.scanner.passive.checks.ws_no_input_sanitization import WsNoInputSanitizationCheck
from modules.scanner.passive.checks.ws_no_rate_limit import WsNoRateLimitCheck
from modules.scanner.passive.checks.ws_no_wss import WsNoWssCheck
from modules.scanner.passive.checks.ws_origin_validation import WsOriginValidationCheck
from modules.scanner.passive.checks.ws_sensitive_data import WsSensitiveDataCheck
from modules.scanner.passive.checks.xpath_more import XpathMoreCheck
from modules.scanner.passive.checks.xss_document_referrer import XssDocumentReferrerCheck
from modules.scanner.passive.checks.xss_document_write import XssDocumentWriteCheck
from modules.scanner.passive.checks.xss_dynamic_import import XssDynamicImportCheck
from modules.scanner.passive.checks.xss_error_stack import XssErrorStackCheck
from modules.scanner.passive.checks.xss_eval_settimeout import XssEvalSetTimeoutCheck
from modules.scanner.passive.checks.xss_import import XssImportCheck
from modules.scanner.passive.checks.xss_innerhtml import XssInnerhtmlCheck
from modules.scanner.passive.checks.xss_insertadjacenthtml import XssInsertadjacenthtmlCheck
from modules.scanner.passive.checks.xss_meta_refresh import XssMetaRefreshCheck
from modules.scanner.passive.checks.xss_more_variants import XssMoreVariantsCheck
from modules.scanner.passive.checks.xss_new_function import XssNewFunctionCheck
from modules.scanner.passive.checks.xss_outerhtml import XssOuterhtmlCheck
from modules.scanner.passive.checks.xss_postmessage import XssPostmessageCheck
from modules.scanner.passive.checks.xss_reflected_fragment import XssReflectedFragmentCheck
from modules.scanner.passive.checks.xss_svg_animate import XssSvgAnimateCheck
from modules.scanner.passive.checks.xss_window_name import XssWindowNameCheck
from modules.scanner.passive.checks.xxe_detection import XxeDetectionCheck
from modules.scanner.passive.checks.xxe_docx_upload import XxeDocxUploadCheck
from modules.scanner.passive.checks.xxe_external_dtd import XxeExternalDtdCheck
from modules.scanner.passive.checks.xxe_odt_upload import XxeOdtUploadCheck
from modules.scanner.passive.checks.xxe_parameter_entities import XxeParameterEntitiesCheck
from modules.scanner.passive.checks.xxe_soap import XxeSoapCheck
from modules.scanner.passive.checks.xxe_svg_upload import XxeSvgUploadCheck
from modules.scanner.passive.checks.xxe_xinclude import XxeXincludeCheck
from modules.scanner.passive.checks.xxe_xlsx_upload import XxeXlsxUploadCheck

logger = logging.getLogger(__name__)


class PassiveScanner:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.seen_findings = set()
        self.checks: list[BaseCheck] = [
            AlapcaCheck(),
            AuthAccountLockoutCheck(),
            AuthDefaultCredsCheck(),
            AuthLoginOverHttpCheck(),
            AuthLogoutInvalidationCheck(),
            AuthPasswordAutocompleteCheck(),
            AuthRememberMeCheck(),
            AuthSessionRotationCheck(),
            AuthSessionUrlCheck(),
            AuthVerboseErrorsCheck(),
            AuthWeakPasswordPolicyCheck(),
            Biz2faBypassCheck(),
            BizCaptchaDirectCheck(),
            BizCaptchaResponseCheck(),
            BizIntegerOverflowCheck(),
            BizNegativeValueCheck(),
            BizOtpBypassCheck(),
            BizPriceManipulationCheck(),
            BizQuantityCheck(),
            BizSkipStepCheck(),
            BizUnlimitedUploadCheck(),
            CacheDeceptionCtCheck(),
            CacheHostHeaderCheck(),
            CacheKeyInjectionCheck(),
            CachePoisoningCheck(),
            CachePrivateDataCheck(),
            CacheStaticDynamicCheck(),
            CacheUnkeyedHeaderCheck(),
            CacheUnkeyedQueryCheck(),
            CacheXfhCheck(),
            CdnMisconfigCheck(),
            CdnOriginIpCheck(),
            ClickjackingCheck(),
            CmdInjectionMoreCheck(),
            CookieAttributesCheck(),
            CookieFlagsCheck(),
            CorsCredentialsAllCheck(),
            CorsExposedHeadersCheck(),
            CorsMaxAgeLongCheck(),
            CorsMisconfigCheck(),
            CorsNullOriginCheck(),
            CorsOriginReflectionCheck(),
            CorsPreflightBypassCheck(),
            CorsVaryHeaderCheck(),
            CorsWildcardCredsCheck(),
            CspBypassCheck(),
            CspEvalCheck(),
            CsrfTokenCheck(),
            DirectoryListingCheck(),
            DomClobberingCheck(),
            DotnetDeserializationCheck(),
            ElInjectionCheck(),
            ElmaInjectionCheck(),
            EmailDisclosureCheck(),
            FileUploadMisconfigCheck(),
            FileUploadMoreCheck(),
            GraphqlAliasesCheck(),
            GraphqlBatchingCheck(),
            GraphqlCsrfCheck(),
            GraphqlDebugCheck(),
            GraphqlDepthCheck(),
            GraphqlFieldSuggestionsCheck(),
            GraphQLIntrospectionCheck(),
            GraphqlNoAuthCheck(),
            HstsCheck(),
            Http2DowngradeCheck(),
            HttpMethodsCheck(),
            HttpParamPollutionCheck(),
            InfoDebugEndpointsCheck(),
            InfoDirectoryListing2Check(),
            InfoEnvFileCheck(),
            InfoGitConfigCheck(),
            InfoInternalIpCheck(),
            InfoLeakageCheck(),
            InfoPhpinfoCheck(),
            InfoServerStatusCheck(),
            InfoStackTraceCheck(),
            InsecureCookiesCheck(),
            JavaDeserializationCheck(),
            JsClobberingCheck(),
            JwtAlgNoneCheck(),
            JwtCritBypassCheck(),
            JwtExpiredTokenCheck(),
            JwtExposureCheck(),
            JwtJkuBypassCheck(),
            JwtJwkInjectionCheck(),
            JwtKidInjectionCheck(),
            JwtNoneAlgCheck(),
            JwtTypManipulationCheck(),
            JwtWeakSecretCheck(),
            LdapMoreCheck(),
            MethodOverrideCheck(),
            MiscConnectMethodCheck(),
            MiscCrlfLogCheck(),
            MiscCsvInjectionCheck(),
            MiscDeleteMethodCheck(),
            MiscHeadEnabledCheck(),
            MiscHostHeaderPasswordResetCheck(),
            MiscHttp09Check(),
            MiscMassAssignmentCheck(),
            MiscOptionsMethodCheck(),
            MiscPatchMethodCheck(),
            MiscPutMethodCheck(),
            MiscResetTokenEmailCheck(),
            MiscResponseSplittingCheck(),
            MiscTraceMethodCheck(),
            MiscUrlRedirectorCheck(),
            MiscWeakResetTokenCheck(),
            MissingHeadersCheck(),
            NosqlMoreCheck(),
            OpenBucketCheck(),
            OpenRedirectCheck(),
            OpenRedirectPassiveCheck(),
            OpenApiExposureCheck(),
            PathTraversalMoreCheck(),
            PathTraversalPassiveCheck(),
            PostmessageOriginValidationCheck(),
            PrototypePollutionClientCheck(),
            PrototypePollutionServerCheck(),
            RaceCouponCheck(),
            RaceEmailVerifyCheck(),
            RaceFileUploadCheck(),
            RacePaymentCheck(),
            RaceRateLimitCheck(),
            RateLimitingCheck(),
            SecurityTxtCheck(),
            SensitiveDataExposureCheck(),
            ServerSideIncludesCheck(),
            SmtpInjectionCheck(),
            SmugglingChunkedParsingCheck(),
            SmugglingClClCheck(),
            SmugglingClTeCheck(),
            SmugglingContentLengthCheck(),
            SmugglingH2DowngradeCheck(),
            SmugglingH2SmugglingCheck(),
            SmugglingTeClCheck(),
            SmugglingTeTeCheck(),
            SopBypassCheck(),
            SopDocumentDomainCheck(),
            SopWindowOpenCheck(),
            SpelInjectionCheck(),
            SqliBooleanCheck(),
            SqliBooleanIndicatorsCheck(),
            SqliCookieReflectionCheck(),
            SqliErrorMssqlCheck(),
            SqliErrorMysqlCheck(),
            SqliErrorOracleCheck(),
            SqliErrorPostgresqlCheck(),
            SqliHttpHeaderCheck(),
            SqliJsonResponseCheck(),
            SqliMoreVariantsCheck(),
            SqliStackedMssqlCheck(),
            SqliStackedPostgresqlCheck(),
            SqliTimeIndicatorsCheck(),
            SqliTimeMssqlCheck(),
            SqliTimeMysqlCheck(),
            SqliTimePostgresqlCheck(),
            SqliXmlResponseCheck(),
            SslIssuesCheck(),
            SsrfMoreCheck(),
            SstiDetectionCheck(),
            SstiErbCheck(),
            SstiFreemarkerCheck(),
            SstiHandlebarsCheck(),
            SstiJadeCheck(),
            SstiJinja2Check(),
            SstiMakoCheck(),
            SstiMustacheCheck(),
            SstiSmartyCheck(),
            SstiTornadoCheck(),
            SstiTwigCheck(),
            SstiVelocityCheck(),
            SubdomainTakeoverCheck(),
            TimingHeadersCheck(),
            WebCachePoisoningCheck(),
            WsCrossOriginCheck(),
            WsMessageInjectionCheck(),
            WsNoAuthCheck(),
            WsNoInputSanitizationCheck(),
            WsNoRateLimitCheck(),
            WsNoWssCheck(),
            WsOriginValidationCheck(),
            WsSensitiveDataCheck(),
            XpathMoreCheck(),
            XssDocumentReferrerCheck(),
            XssDocumentWriteCheck(),
            XssDynamicImportCheck(),
            XssErrorStackCheck(),
            XssEvalSetTimeoutCheck(),
            XssImportCheck(),
            XssInnerhtmlCheck(),
            XssInsertadjacenthtmlCheck(),
            XssMetaRefreshCheck(),
            XssMoreVariantsCheck(),
            XssNewFunctionCheck(),
            XssOuterhtmlCheck(),
            XssPostmessageCheck(),
            XssReflectedFragmentCheck(),
            XssSvgAnimateCheck(),
            XssWindowNameCheck(),
            XxeDetectionCheck(),
            XxeDocxUploadCheck(),
            XxeExternalDtdCheck(),
            XxeOdtUploadCheck(),
            XxeParameterEntitiesCheck(),
            XxeSoapCheck(),
            XxeSvgUploadCheck(),
            XxeXincludeCheck(),
            XxeXlsxUploadCheck(),
            # Advanced passive checks (deepseek v4-pro)
            PassiveInfoDisclosureCheck(),
            PassiveTechFingerprintCheck(),
        ]

    def register(self):
        self.event_bus.subscribe("response.received", self._on_response)

    def unregister(self):
        self.event_bus.unsubscribe("response.received", self._on_response)

    async def _on_response(self, event):
        for check in self.checks:
            try:
                results = await check.run(event, {})
                
                unique_results = []
                for result in results:
                    if result.triggered:
                        dedup_key = f"{result.cwe}_{result.title}_{event.get('url', '')}"
                        if dedup_key in self.seen_findings:
                            continue
                        self.seen_findings.add(dedup_key)
                        
                        cvss_info = get_cvss_for_cwe(result.cwe) if result.cwe else None
                        if cvss_info:
                            result.cvss_score = cvss_info["score"]
                            result.cvss_vector = cvss_info["vector"]
                            if not hasattr(result, 'severity') or result.severity == "info":
                                result.severity = cvss_info["severity"]
                        
                        unique_results.append(result)
                        logger.info(
                            "Passive check %s triggered: %s (CVSS: %s)",
                            check.name, result.title, getattr(result, 'cvss_score', 'N/A')
                        )
                
                if unique_results:
                    await persist_results(self.event_bus, unique_results, event, check.name, source="passive")
            except Exception as e:
                logger.error("Passive check %s failed: %s", check.name, e)

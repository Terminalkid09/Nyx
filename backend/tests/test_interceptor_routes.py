import pytest
import uuid


class TestRuleCreateModel:
    def test_rule_create_defaults(self):
        from api.routes.interceptor import RuleCreate
        rule = RuleCreate(name="test-rule")
        assert rule.name == "test-rule"
        assert rule.scope == "request"
        assert rule.intercept_on_match is True
        assert rule.match_type is None
        assert rule.match_pattern is None
        assert rule.is_regex is False
        assert rule.order == 0
        assert rule.session_id is None

    def test_rule_create_with_all_fields(self):
        from api.routes.interceptor import RuleCreate
        sid = uuid.uuid4()
        rule = RuleCreate(
            session_id=sid,
            name="advanced",
            scope="response",
            intercept_on_match=False,
            match_type="header",
            match_pattern="X-Custom: value",
            is_regex=True,
            order=10,
        )
        assert rule.session_id == sid
        assert rule.name == "advanced"
        assert rule.scope == "response"
        assert rule.intercept_on_match is False
        assert rule.match_type == "header"
        assert rule.match_pattern == "X-Custom: value"
        assert rule.is_regex is True
        assert rule.order == 10

    def test_rule_create_model_dump(self):
        from api.routes.interceptor import RuleCreate
        rule = RuleCreate(name="test", scope="request")
        data = rule.model_dump()
        assert data["name"] == "test"
        assert data["scope"] == "request"
        assert data["intercept_on_match"] is True


class TestRuleUpdateModel:
    def test_rule_update_empty(self):
        from api.routes.interceptor import RuleUpdate
        rule = RuleUpdate()
        dumped = rule.model_dump(exclude_none=True)
        assert dumped == {}

    def test_rule_update_partial(self):
        from api.routes.interceptor import RuleUpdate
        rule = RuleUpdate(name="updated", enabled=False)
        data = rule.model_dump(exclude_none=True)
        assert data == {"name": "updated", "enabled": False}

    def test_rule_update_all_fields(self):
        from api.routes.interceptor import RuleUpdate
        rule = RuleUpdate(
            name="n",
            enabled=True,
            scope="response",
            intercept_on_match=False,
            match_type="body",
            match_pattern="error",
            is_regex=True,
            order=5,
        )
        data = rule.model_dump(exclude_none=True)
        assert data["name"] == "n"
        assert data["enabled"] is True
        assert data["scope"] == "response"
        assert data["order"] == 5


class TestRuleResponseModel:
    def test_rule_response_with_attributes(self):
        from api.routes.interceptor import RuleResponse
        rid = uuid.uuid4()
        sid = uuid.uuid4()
        rule = RuleResponse(
            id=rid,
            session_id=sid,
            enabled=True,
            name="test",
            scope="request",
            intercept_on_match=True,
            match_type=None,
            match_pattern=None,
            is_regex=False,
            order=0,
        )
        assert rule.id == rid
        assert rule.session_id == sid
        assert rule.enabled is True
        assert rule.name == "test"
        assert rule.scope == "request"
        assert rule.intercept_on_match is True
        assert rule.match_type is None
        assert rule.match_pattern is None
        assert rule.is_regex is False
        assert rule.order == 0
        assert rule.model_config["from_attributes"] is True

    def test_rule_response_model_dump(self):
        from api.routes.interceptor import RuleResponse
        rule = RuleResponse(
            id=uuid.uuid4(),
            session_id=None,
            enabled=False,
            name="a",
            scope="response",
            intercept_on_match=False,
            match_type="header",
            match_pattern="X: Y",
            is_regex=True,
            order=99,
        )
        data = rule.model_dump()
        assert data["name"] == "a"
        assert data["scope"] == "response"
        assert data["match_type"] == "header"
        assert data["is_regex"] is True
        assert data["order"] == 99


class TestForwardModifications:
    def test_forward_modifications_defaults(self):
        from api.routes.interceptor import ForwardModifications
        mod = ForwardModifications()
        assert mod.method is None
        assert mod.url is None
        assert mod.headers is None
        assert mod.body is None

    def test_forward_modifications_with_values(self):
        from api.routes.interceptor import ForwardModifications
        mod = ForwardModifications(
            method="POST",
            url="https://example.com/new",
            headers={"X-Custom": "value"},
            body='{"key": "val"}',
        )
        assert mod.method == "POST"
        assert mod.url == "https://example.com/new"
        assert mod.headers == {"X-Custom": "value"}
        assert mod.body == '{"key": "val"}'

    def test_forward_modifications_model_dump(self):
        from api.routes.interceptor import ForwardModifications
        mod = ForwardModifications(method="PUT")
        data = mod.model_dump(exclude_none=True)
        assert data == {"method": "PUT"}

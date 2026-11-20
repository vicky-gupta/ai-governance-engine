# Unit tests for aigov.rego. They run with `go test ./internal/policy/`
# (or `opa test policies/` if you have the OPA command-line tool).
package aigov_test

import data.aigov

limited := {"name": "support-bot", "risk_tier": "limited"}

high := {"name": "loan-agent", "risk_tier": "high"}

test_clean_request_passes if {
	inp := {"system": limited, "messages": [{"role": "user", "text": "What are your opening hours?"}]}
	count(aigov.deny) == 0 with input as inp
	count(aigov.hold) == 0 with input as inp
}

test_blocked_term_is_denied_in_any_case if {
	inp := {"system": limited, "messages": [{"role": "user", "text": "Summarise the PROJECT FALCON roadmap"}]}
	aigov.deny == {`message mentions blocked term "project falcon"`} with input as inp
}

test_credit_decision_by_high_risk_system_is_held if {
	inp := {"system": high, "messages": [{"role": "user", "text": "Please approve the loan for applicant [EMAIL_1]"}]}
	count(aigov.hold) == 1 with input as inp
}

test_credit_question_by_limited_system_is_not_held if {
	inp := {"system": limited, "messages": [{"role": "user", "text": "Please approve the loan"}]}
	count(aigov.hold) == 0 with input as inp
}

test_credit_words_in_system_prompt_are_not_held if {
	inp := {"system": high, "messages": [{"role": "system", "text": "Never approve a loan yourself."}]}
	count(aigov.hold) == 0 with input as inp
}

test_max_tokens_by_tier if {
	aigov.max_tokens == 1024 with input as {"system": high, "messages": []}
	aigov.max_tokens == 4096 with input as {"system": limited, "messages": []}
}


# The same look-alike characters must not get a blocked term past the
# request check either.
test_blocked_term_with_lookalike_space_is_denied if {
	count(aigov.deny) == 1 with input as {
		"system": {"name": "x", "risk_tier": "limited"},
		"messages": [{"role": "user", "text": "Status of Project\u202fFalcon?"}],
	}
}
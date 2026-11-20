package aigov_response_test

import data.aigov
import data.aigov.response

bot := {"name": "support-bot", "risk_tier": "limited"}

loan := {"name": "loan-agent", "risk_tier": "high"}

test_clean_answer_allowed if {
	count(response.deny) == 0 with input as {"system": bot, "text": "Your order ships today.", "pii": []}
}

test_blocked_term_in_answer_denied if {
	response.deny["the answer mentions \"project falcon\""] with input as {
		"system": bot, "text": "Project Falcon launches in May.", "pii": [],
	}
}

test_pii_in_limited_answer_not_denied if {
	# Removed by the gateway, not stopped.
	count(response.deny) == 0 with input as {"system": bot, "text": "IBAN [REDACTED_IBAN]", "pii": ["IBAN"]}
}

test_pii_in_high_risk_answer_denied if {
	count(response.deny) == 1 with input as {"system": loan, "text": "...", "pii": ["IBAN"]}
}

test_high_risk_may_not_stream if {
	count(aigov.deny) == 1 with input as {"system": loan, "stream": true, "messages": []}
}

test_limited_may_stream if {
	count(aigov.deny) == 0 with input as {"system": bot, "stream": true, "messages": []}
}


# Models write look-alike characters: a narrow no-break space (\u202f),
# a no-break space (\u00a0), a non-breaking hyphen (\u2011), curly quotes,
# markdown. They must not get a blocked term through.
test_blocked_term_in_any_spelling if {
	spellings := [
		"Project FALCON launches",
		"Project\u202fFALCON launches",
		"Project\u00a0Falcon launches",
		"Project\u2011Falcon launches",
		"Project **FALCON** launches",
		"Project \u201cFALCON\u201d launches",
		"Project  FALCON launches",
	]
	every text in spellings {
		count(response.deny) == 1 with input as {"system": bot, "text": text, "pii": []}
	}
}

test_unrelated_text_not_denied if {
	count(response.deny) == 0 with input as {"system": bot, "text": "A falcon flew over the project site.", "pii": []}
}
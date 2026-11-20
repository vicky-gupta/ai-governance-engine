# Rules for the text of a model's answer, checked before it reaches the
# caller (for streamed answers: right after, see the output guard).
#
# The gateway evaluates data.aigov.response and reads:
#   deny - reasons to stop the answer
#
# input contains:
#   system: {name, owner, risk_tier}
#   model
#   text:   the answer text (all choices joined)
#   pii:    the kinds of personal data found in it, e.g. ["IBAN", "EMAIL"]
#           (kinds only, never the values)
#
# Personal data in an answer is removed by the gateway itself; these rules
# decide when an answer has to be stopped completely.
package aigov.response

import data.aigov.blocked_terms
import data.aigov.mentions

# Confidential terms must not leak out in answers either.
deny contains msg if {
	some term in blocked_terms
	contains(lower(input.text), term)
	msg := sprintf("the answer mentions %q", [term])
}

deny contains msg if {
	some term in blocked_terms
	mentions(input.text, term)
	msg := sprintf("the answer mentions %q", [term])
}

# High-risk systems: an answer with personal data in it is not cleaned up
# and passed on, it is stopped.
deny contains msg if {
	input.system.risk_tier == "high"
	count(input.pii) > 0
	msg := sprintf("the answer of a high-risk system contained personal data (%s)", [concat(", ", input.pii)])
}
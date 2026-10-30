"""Isolated Learn-then-Test port for one Bernoulli task-failure risk.

This implements exact binomial lower-tail p-values and Bonferroni selection,
not the paper's model experiments.  Predictors, task loss and cost order must
be fixed before calibration.  No held-out data, models, files or services are
read here.  Statistical validity additionally requires i.i.d. calibration
units from the deployment population; this module cannot verify that premise.

Sources: arxiv.org/html/2110.01052v5, sections 2.1, 2.3 and 3.2.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
import math


VERSION = "ltt_bernoulli_exact_bonferroni_v1"
Probability = Fraction | int | float | str


def _probability(value: Probability, *, interior: bool) -> Fraction:
    """Floats mean their displayed decimal value, not their binary expansion."""
    if type(value) is bool or type(value) not in (Fraction, int, float, str):
        raise ValueError("invalid_probability")
    if type(value) is float and not math.isfinite(value):
        raise ValueError("invalid_probability")
    try:
        result = Fraction(str(value)) if type(value) is float else Fraction(value)
    except (ValueError, ZeroDivisionError, OverflowError):
        raise ValueError("invalid_probability") from None
    if not (0 < result < 1 if interior else 0 <= result <= 1):
        raise ValueError("probability_out_of_range")
    return result


def _ids(values, *, code: str) -> tuple[str, ...]:
    if (not isinstance(values, (tuple, list)) or not values
            or any(type(item) is not str or not item or item != item.strip() for item in values)
            or len(set(values)) != len(values)):
        raise ValueError(code)
    return tuple(values)


def _exact(value: Fraction) -> dict:
    return {"numerator": value.numerator, "denominator": value.denominator}


@dataclass(frozen=True)
class LTTPlan:
    """Immutable finite hypothesis family and predeclared cost tie-break order.

    A digest records the declaration; it cannot prove when the plan was made.
    These are configuration identifiers, not model implementations or ACLs.
    """
    config_ids: tuple[str, ...]
    alpha: Fraction
    delta: Fraction
    cost_order: tuple[str, ...]

    def __post_init__(self):
        if type(self.config_ids) is not tuple or type(self.cost_order) is not tuple:
            raise ValueError("plan_requires_immutable_ids")
        _ids(self.config_ids, code="invalid_config_ids")
        _ids(self.cost_order, code="invalid_cost_order")
        if set(self.config_ids) != set(self.cost_order):
            raise ValueError("cost_order_must_cover_fixed_family")
        if type(self.alpha) is not Fraction or type(self.delta) is not Fraction:
            raise ValueError("plan_requires_exact_probabilities")
        _probability(self.alpha, interior=True)
        _probability(self.delta, interior=True)

    def to_dict(self) -> dict:
        return {"version": VERSION, "config_ids": list(self.config_ids),
                "alpha_exact": _exact(self.alpha), "delta_exact": _exact(self.delta),
                "cost_order": list(self.cost_order), "risk": "unconditional_bernoulli_task_failure",
                "correction": "bonferroni", "null": "R(config) > alpha"}

    @property
    def sha256(self) -> str:
        raw = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


def make_plan(config_ids: Sequence[str], *, alpha: Probability, delta: Probability,
              cost_order: Sequence[str]) -> LTTPlan:
    """Declare all tested configurations and the cheapest-first fixed ordering."""
    return LTTPlan(_ids(config_ids, code="invalid_config_ids"),
                   _probability(alpha, interior=True), _probability(delta, interior=True),
                   _ids(cost_order, code="invalid_cost_order"))


def binomial_lower_tail(failures: int, n: int, alpha: Probability) -> Fraction:
    """Return P[Binomial(n, alpha) <= failures] exactly, without HB's factor e.

    Under the fixed-configuration null R > alpha, lower observed failure
    counts are evidence against the null.  Equality is included in the CDF.
    The primitive supports n=0 and alpha endpoints as mathematical cases;
    calibration itself rejects zero observations and endpoint risk targets.
    """
    if type(n) is not int or n < 0 or type(failures) is not int or not 0 <= failures <= n:
        raise ValueError("invalid_binomial_counts")
    probability = _probability(alpha, interior=False)
    if failures == n or probability == 0:
        return Fraction(1)
    if probability == 1:
        return Fraction(0)
    # Put all terms over one integer denominator rather than accumulating
    # rounded probabilities (or repeatedly reducing Fraction additions).
    a, denominator = probability.numerator, probability.denominator
    b = denominator - a
    numerator = sum(math.comb(n, j) * a ** j * b ** (n - j)
                    for j in range(failures + 1))
    return Fraction(numerator, denominator ** n)


def _family(plan, observations):
    if type(plan) is not LTTPlan:
        raise ValueError("invalid_ltt_plan")
    if not isinstance(observations, Mapping) or set(observations) != set(plan.config_ids):
        raise ValueError("observations_must_cover_fixed_family")


def calibrate_counts(plan: LTTPlan, failures_by_config: Mapping[str, int], *, n: int) -> dict:
    """Test every fixed configuration using the same positive calibration n.

    Counts must include every task, including a refused/failed task if the
    predeclared loss defines it as a failure.  No check/test-set input exists.
    Correlated configurations on the same tasks are permitted by Bonferroni;
    arbitrary dependence between calibration tasks is not thereby justified.
    """
    _family(plan, failures_by_config)
    if type(n) is not int or n <= 0:
        raise ValueError("positive_calibration_n_required")
    if any(type(k) is not int or not 0 <= k <= n for k in failures_by_config.values()):
        raise ValueError("invalid_failure_count")
    threshold = plan.delta / len(plan.config_ids)
    rows, qualified = [], []
    for config in plan.config_ids:
        k = failures_by_config[config]
        p_value = binomial_lower_tail(k, n, plan.alpha)
        passed = p_value <= threshold
        if passed:
            qualified.append(config)
        rows.append({"config_id": config, "n": n, "failures": k,
                     "empirical_risk": k / n, "p_value": float(p_value),
                     "p_value_exact": _exact(p_value), "qualified": passed})
    selected = next((config for config in plan.cost_order if config in qualified), None)
    return {"version": VERSION, "status": "qualified" if qualified else "no_qualified_configuration",
            "plan": plan.to_dict(), "plan_sha256": plan.sha256,
            "calibration_n": n, "family_size": len(plan.config_ids),
            "alpha": float(plan.alpha), "delta": float(plan.delta),
            "bonferroni_threshold": float(threshold), "bonferroni_threshold_exact": _exact(threshold),
            "rows": rows, "qualified_configs": qualified, "selected_config": selected,
            "selection_rule": "first_qualified_in_predeclared_cost_order",
            "p_value_display_only": "float fields are approximations; qualification uses exact fractions",
            "guarantee_scope": "conditional_on_fixed_family_valid_bernoulli_losses_and_iid_tasks",
            "human_semantic_validation": None, "paper_experiments_reproduced": False}


def calibrate_bernoulli(plan: LTTPlan, losses_by_config: Mapping[str, Sequence[int]]) -> dict:
    """Count strict integer 0/1 task losses, retaining the complete fixed family."""
    _family(plan, losses_by_config)
    lengths, counts = set(), {}
    for config in plan.config_ids:
        losses = losses_by_config[config]
        if not isinstance(losses, (list, tuple)):
            raise ValueError("bernoulli_losses_must_be_sequence")
        if any(type(loss) is not int or loss not in (0, 1) for loss in losses):
            raise ValueError("loss_must_be_strict_integer_zero_or_one")
        lengths.add(len(losses))
        counts[config] = sum(losses)
    if len(lengths) != 1:
        raise ValueError("configurations_require_same_task_count")
    return calibrate_counts(plan, counts, n=lengths.pop())

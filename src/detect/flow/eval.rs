// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a guard means
//!
//! [`super::expr`] parses a guard into a tree; this evaluates that tree against a
//! running flow's variable [environment](Env) to the one boolean the interpreter
//! acts on — run this step, or emit this finding, or not. It is the runtime half
//! of the guard language, so unlike the grammar it may reach into the crate: an
//! ordered comparison defers to [`crate::version`] so a flow guard and the CVE
//! correlator rank a version string the same way.
//!
//! ## Two ways a guard fails closed
//!
//! A guard that cannot be answered answers *no*, never *maybe*:
//!
//! - **A guard that does not parse** is treated as unmet. In a validated corpus
//!   this cannot happen — the build rejects an unparseable guard (a later
//!   increment) — but until then, and for a hand-built flow in a test, an
//!   unreadable guard suppresses its step or finding rather than firing it.
//! - **A comparison on an unbound variable** is unmet. `version < '2'` when
//!   `version` was never bound is false, not an error and not true, which is why
//!   a conditional step guards `bound(version) and version < '2'`: the `and`
//!   short-circuits and the comparison is never reached against nothing.

use std::cmp::Ordering;

use crate::version::version_cmp;

use super::Env;
use super::expr::{self, Expr, Operand, RelOp};

/// Whether a `when` clause holds against `env`.
///
/// `matched` carries the enclosing step's match result where one is in scope — a
/// finding's guard may read `matched`, and receives `Some`; a step's own guard
/// runs before the step matches anything and receives `None`, so a `matched` in
/// it reads as false. An absent clause always holds.
pub(super) fn holds(when: Option<&str>, env: &Env, matched: Option<bool>) -> bool {
    match when {
        None => true,
        Some(source) => match expr::parse(source) {
            Ok(expr) => eval(&expr, env, matched),
            Err(_) => false,
        },
    }
}

/// Evaluates a parsed guard against the environment.
fn eval(expr: &Expr, env: &Env, matched: Option<bool>) -> bool {
    match expr {
        Expr::Or(left, right) => eval(left, env, matched) || eval(right, env, matched),
        Expr::And(left, right) => eval(left, env, matched) && eval(right, env, matched),
        Expr::Not(inner) => !eval(inner, env, matched),
        Expr::Matched => matched.unwrap_or(false),
        Expr::Bound(name) => env.contains_key(name),
        Expr::Unbound(name) => !env.contains_key(name),
        Expr::Compare { left, op, right } => compare(left, *op, right, env),
    }
}

/// Evaluates one comparison, failing closed if either operand is an unbound
/// variable.
fn compare(left: &Operand, op: RelOp, right: &Operand, env: &Env) -> bool {
    let (Some(left), Some(right)) = (resolve(left, env), resolve(right, env)) else {
        return false;
    };
    match op {
        RelOp::Eq => left.equals(&right),
        RelOp::Ne => !left.equals(&right),
        RelOp::Lt => left.order(&right) == Ordering::Less,
        RelOp::Le => left.order(&right) != Ordering::Greater,
        RelOp::Gt => left.order(&right) == Ordering::Greater,
        RelOp::Ge => left.order(&right) != Ordering::Less,
    }
}

/// A comparison operand resolved to the value it stands for, or [`None`] for a
/// variable that is not bound.
fn resolve(operand: &Operand, env: &Env) -> Option<Value> {
    match operand {
        Operand::Int(value) => Some(Value::Number(*value)),
        Operand::Text(text) => Some(Value::Text(text.clone())),
        Operand::Var(name) => env.get(name).map(|value| Value::Text(value.clone())),
    }
}

/// A resolved operand. A variable always resolves to [`Text`](Value::Text) — the
/// environment holds only strings — so the numeric path is reached exactly when
/// *both* sides were written as integer literals, which is the rule the grammar
/// promises.
enum Value {
    Number(i64),
    Text(String),
}

impl Value {
    /// Equality: numeric between two integer literals, string-coerced otherwise
    /// — total and always defined, so `count == 3` and `name == 'nginx'` both
    /// mean what they read as.
    fn equals(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => a == b,
            _ => self.text() == other.text(),
        }
    }

    /// Order: numeric between two integer literals, [dotted version](version_cmp)
    /// otherwise — so `8.10.0 < 8.3.1` is false (10 outranks 3), the version
    /// range check that is the whole reason the operator earns its place.
    fn order(&self, other: &Value) -> Ordering {
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => a.cmp(b),
            _ => version_cmp(&self.text(), &other.text()),
        }
    }

    /// The string form an operand coerces to when it is compared as text.
    fn text(&self) -> String {
        match self {
            Value::Number(value) => value.to_string(),
            Value::Text(text) => text.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn an_absent_guard_always_holds() {
        assert!(holds(None, &Env::new(), Some(false)));
    }

    #[test]
    fn matched_reads_the_step_result_only_where_one_is_in_scope() {
        // A finding's guard: `matched` is the step's result.
        assert!(holds(Some("matched"), &Env::new(), Some(true)));
        assert!(!holds(Some("matched"), &Env::new(), Some(false)));
        // A step's own guard runs before any match, so `matched` is out of scope
        // and reads false rather than firing the step early.
        assert!(!holds(Some("matched"), &Env::new(), None));
    }

    #[test]
    fn bound_and_unbound_test_presence() {
        let env = env(&[("version", "7.2.4")]);
        assert!(holds(Some("bound(version)"), &env, None));
        assert!(!holds(Some("unbound(version)"), &env, None));
        assert!(!holds(Some("bound(missing)"), &env, None));
        assert!(holds(Some("unbound(missing)"), &env, None));
    }

    #[test]
    fn ordered_comparison_ranks_versions_numerically_not_lexically() {
        let affected = env(&[("version", "8.2.0")]);
        assert!(holds(Some("version < '8.3.1'"), &affected, None));

        // The lexical trap the operator exists to avoid: 8.10.0 is *newer* than
        // 8.3.1, so it is not in the affected `< 8.3.1` range — a lexical `<`
        // would wrongly report it, understating nothing and over-reporting a
        // patched server as vulnerable.
        let patched = env(&[("version", "8.10.0")]);
        assert!(!holds(Some("version < '8.3.1'"), &patched, None));
    }

    #[test]
    fn equality_is_numeric_between_integers_and_textual_otherwise() {
        assert!(holds(Some("3 == 3"), &Env::new(), None));
        assert!(holds(Some("3 != 4"), &Env::new(), None));
        // A variable holds a string; comparing it to an integer coerces to text.
        let counts = env(&[("count", "3")]);
        assert!(holds(Some("count == 3"), &counts, None));
        let names = env(&[("name", "apache")]);
        assert!(holds(Some("name != 'nginx'"), &names, None));
    }

    #[test]
    fn a_comparison_on_an_unbound_variable_fails_closed() {
        // No `version` bound: the comparison is false, not an error and not true.
        assert!(!holds(Some("version < '2'"), &Env::new(), None));
        // Which is why the conditional-step idiom guards it — the `and`
        // short-circuits before the comparison is reached against nothing.
        assert!(!holds(
            Some("bound(version) and version < '2'"),
            &Env::new(),
            None
        ));
    }

    #[test]
    fn boolean_combinators_short_circuit_with_the_right_precedence() {
        let env = env(&[("version", "8.2.0")]);
        // The Grafana "version known but leak unconfirmed" finding guard.
        assert!(holds(
            Some("not matched and bound(version)"),
            &env,
            Some(false)
        ));
        assert!(!holds(
            Some("not matched and bound(version)"),
            &env,
            Some(true)
        ));
        // `or` is looser than `and`.
        assert!(holds(
            Some("matched and unbound(version) or bound(version)"),
            &env,
            Some(true)
        ));
    }

    #[test]
    fn an_unparseable_guard_is_treated_as_unmet() {
        assert!(!holds(Some("this is not a guard"), &Env::new(), Some(true)));
    }
}

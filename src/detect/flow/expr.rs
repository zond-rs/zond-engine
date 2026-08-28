// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The guard expression grammar
//!
//! A guard is the one place a Tier-1 flow makes a decision: a step's `when`
//! decides whether the step runs, a finding's `when` decides whether it fires.
//! This module is the guard *as syntax* — an [`Expr`] tree and the [`parse`]
//! that builds one from the string a flow author wrote. What a parsed guard
//! *means* against a running flow's variables lives beside the interpreter
//! ([`super::eval`]); the split is deliberate, and it is the same split the
//! service signatures already keep.
//!
//! ## Shared verbatim with the build
//!
//! Like [`fingerprint::pattern`](crate::fingerprint) and the signature schema,
//! this module carries no dependency on the rest of the crate — only [`std`] —
//! so `build.rs` can load it with `#[path]` and reject a malformed guard *at
//! build time*, with the exact parser the runtime uses. A guard the build
//! accepts is a guard the interpreter can read, because both read this file.
//! Nothing here reaches a network, a clock, or a variable's value: parsing is
//! pure over the text, which is what lets the build do it.
//!
//! ## The grammar
//!
//! Precedence runs `not` over `and` over `or`, with parentheses to override it.
//! A guard is ultimately a boolean; there is no bare-value truthiness, so a lone
//! variable is a parse error rather than a silent "is it non-empty".
//!
//! ```ebnf
//! expr        = or-expr ;
//! or-expr     = and-expr , { "or" , and-expr } ;
//! and-expr    = not-expr , { "and" , not-expr } ;
//! not-expr    = [ "not" ] , primary ;
//! primary     = "(" , expr , ")" | predicate | comparison ;
//! predicate   = "matched" | "bound" "(" ident ")" | "unbound" "(" ident ")" ;
//! comparison  = operand , rel-op , operand ;
//! rel-op      = "==" | "!=" | "<" | "<=" | ">" | ">=" ;
//! operand     = ident | string-literal | int-literal ;
//! ```
//!
//! There is deliberately no arithmetic, no function call, and no regex operator
//! (matching is `bind`'s job, run once and its result named): a guard that could
//! *compute* would be the first inch of a programming language, and the signal
//! that a detection belongs in the compute tier instead.

use std::fmt;

/// A parsed guard expression — the boolean a `when` clause denotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// `a or b` — true if either side is.
    Or(Box<Expr>, Box<Expr>),
    /// `a and b` — true only if both are.
    And(Box<Expr>, Box<Expr>),
    /// `not a` — the negation.
    Not(Box<Expr>),
    /// `matched` — the enclosing step's combined match result. Meaningful only
    /// where a step result is in scope (a finding's guard), which the build
    /// checks; see [`super::eval`].
    Matched,
    /// `bound(x)` — true if variable `x` has a value.
    Bound(String),
    /// `unbound(x)` — true if variable `x` has none.
    Unbound(String),
    /// `a <op> b` — an equality or ordered comparison of two operands.
    Compare {
        left: Operand,
        op: RelOp,
        right: Operand,
    },
}

/// One side of a comparison: a variable to look up, or a literal to compare
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// A bound variable's name, resolved to its value when the guard runs.
    Var(String),
    /// A string literal, written `'…'` or `"…"`.
    Text(String),
    /// An integer literal — the one operand two of which compare numerically.
    Int(i64),
}

/// The six relational operators. `==`/`!=` are total string equalities (numeric
/// only between two integer literals); `<`/`<=`/`>`/`>=` order by
/// [dotted version](crate::version) unless both sides are integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Why a guard string is not a valid expression. Its [`Display`](fmt::Display)
/// form is the message the build reports beside the offending flow file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The guard is empty or all whitespace.
    Empty,
    /// A character that begins no token — a stray `.`, `&`, or a lone `!`/`=`
    /// that is not part of `!=`/`==`.
    UnexpectedChar(char),
    /// A string literal opened but never closed.
    UnterminatedString,
    /// An integer literal too large for the value it must hold.
    IntOverflow(String),
    /// The parser wanted a specific thing next and did not find it.
    Expected(&'static str),
    /// A complete expression, then more tokens the grammar cannot attach.
    Trailing,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "the guard is empty"),
            ParseError::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            ParseError::UnterminatedString => write!(f, "a string literal is not closed"),
            ParseError::IntOverflow(n) => write!(f, "the number {n} is too large"),
            ParseError::Expected(what) => write!(f, "expected {what}"),
            ParseError::Trailing => write!(f, "unexpected trailing input after the expression"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses a guard string into an [`Expr`], or reports why it is not one.
///
/// Pure over the text: it reads no variable's value and touches nothing outside
/// the string, so the build can call it to validate a guard without running the
/// flow.
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let tokens = lex(input)?;
    if tokens.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.or_expr()?;
    if parser.pos != parser.tokens.len() {
        return Err(ParseError::Trailing);
    }
    Ok(expr)
}

/// A lexical token — the parser's alphabet, one step up from characters.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    And,
    Or,
    Not,
    Matched,
    Bound,
    Unbound,
    LParen,
    RParen,
    Op(RelOp),
    Ident(String),
    Text(String),
    Int(i64),
}

/// Splits a guard string into tokens, or reports the first character that
/// begins none.
fn lex(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '<' | '>' | '=' | '!' => {
                let two = chars.get(i + 1) == Some(&'=');
                let op = match (c, two) {
                    ('<', true) => RelOp::Le,
                    ('<', false) => RelOp::Lt,
                    ('>', true) => RelOp::Ge,
                    ('>', false) => RelOp::Gt,
                    ('=', true) => RelOp::Eq,
                    ('!', true) => RelOp::Ne,
                    // A lone `=` or `!` is not an operator this grammar has.
                    _ => return Err(ParseError::UnexpectedChar(c)),
                };
                tokens.push(Token::Op(op));
                i += if two { 2 } else { 1 };
            }
            '\'' | '"' => {
                let quote = c;
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != quote {
                    j += 1;
                }
                if j >= chars.len() {
                    return Err(ParseError::UnterminatedString);
                }
                tokens.push(Token::Text(chars[start..j].iter().collect()));
                i = j + 1;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let digits: String = chars[start..i].iter().collect();
                let value = digits
                    .parse()
                    .map_err(|_| ParseError::IntOverflow(digits))?;
                tokens.push(Token::Int(value));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                tokens.push(keyword(word));
            }
            _ => return Err(ParseError::UnexpectedChar(c)),
        }
    }
    Ok(tokens)
}

/// A bare word is one of the grammar's keywords or, failing that, an identifier.
/// The keywords are reserved: a flow cannot bind a variable named `matched` or
/// `and`, which is why they are spelled out here rather than left ambiguous.
fn keyword(word: String) -> Token {
    match word.as_str() {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "matched" => Token::Matched,
        "bound" => Token::Bound,
        "unbound" => Token::Unbound,
        _ => Token::Ident(word),
    }
}

/// A recursive-descent parser over the token stream. One pass, no backtracking:
/// each rule consumes exactly the tokens it recognises and hands the rest on.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    /// Consumes the next token if it equals `expected`, else reports `what`.
    fn eat(&mut self, expected: &Token, what: &'static str) -> Result<(), ParseError> {
        if self.peek() == Some(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(ParseError::Expected(what))
        }
    }

    /// `or-expr = and-expr , { "or" , and-expr }` — the loosest binding.
    fn or_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and_expr()?;
        while self.peek() == Some(&Token::Or) {
            self.pos += 1;
            let right = self.and_expr()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `and-expr = not-expr , { "and" , not-expr }`.
    fn and_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.not_expr()?;
        while self.peek() == Some(&Token::And) {
            self.pos += 1;
            let right = self.not_expr()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `not-expr = [ "not" ] , primary` — one optional negation, binding tighter
    /// than `and`, so `not a and b` is `(not a) and b`.
    fn not_expr(&mut self) -> Result<Expr, ParseError> {
        if self.peek() == Some(&Token::Not) {
            self.pos += 1;
            Ok(Expr::Not(Box::new(self.primary()?)))
        } else {
            self.primary()
        }
    }

    /// `primary = "(" , expr , ")" | predicate | comparison`.
    fn primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Token::LParen) => {
                self.pos += 1;
                let inner = self.or_expr()?;
                self.eat(&Token::RParen, "a closing ')'")?;
                Ok(inner)
            }
            Some(Token::Matched) => {
                self.pos += 1;
                Ok(Expr::Matched)
            }
            Some(Token::Bound) => {
                self.pos += 1;
                Ok(Expr::Bound(self.predicate_arg()?))
            }
            Some(Token::Unbound) => {
                self.pos += 1;
                Ok(Expr::Unbound(self.predicate_arg()?))
            }
            _ => self.comparison(),
        }
    }

    /// The `( ident )` a `bound`/`unbound` predicate wraps.
    fn predicate_arg(&mut self) -> Result<String, ParseError> {
        self.eat(&Token::LParen, "'(' after the predicate")?;
        let name = match self.advance() {
            Some(Token::Ident(name)) => name,
            _ => return Err(ParseError::Expected("a variable name")),
        };
        self.eat(&Token::RParen, "a closing ')'")?;
        Ok(name)
    }

    /// `comparison = operand , rel-op , operand`.
    fn comparison(&mut self) -> Result<Expr, ParseError> {
        let left = self.operand()?;
        let op = match self.advance() {
            Some(Token::Op(op)) => op,
            _ => return Err(ParseError::Expected("a comparison operator")),
        };
        let right = self.operand()?;
        Ok(Expr::Compare { left, op, right })
    }

    /// `operand = ident | string-literal | int-literal`.
    fn operand(&mut self) -> Result<Operand, ParseError> {
        match self.advance() {
            Some(Token::Ident(name)) => Ok(Operand::Var(name)),
            Some(Token::Text(text)) => Ok(Operand::Text(text)),
            Some(Token::Int(value)) => Ok(Operand::Int(value)),
            _ => Err(ParseError::Expected("a variable, string, or number")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> Expr {
        parse(input).expect("a valid guard")
    }

    fn var(name: &str) -> Operand {
        Operand::Var(name.to_string())
    }

    fn text(value: &str) -> Operand {
        Operand::Text(value.to_string())
    }

    #[test]
    fn a_bare_predicate_parses() {
        assert_eq!(ok("matched"), Expr::Matched);
        assert_eq!(ok("bound(version)"), Expr::Bound("version".to_string()));
        assert_eq!(ok("unbound(version)"), Expr::Unbound("version".to_string()));
    }

    #[test]
    fn every_relational_operator_parses() {
        for (src, op) in [
            ("v == '1'", RelOp::Eq),
            ("v != '1'", RelOp::Ne),
            ("v < '1'", RelOp::Lt),
            ("v <= '1'", RelOp::Le),
            ("v > '1'", RelOp::Gt),
            ("v >= '1'", RelOp::Ge),
        ] {
            assert_eq!(
                ok(src),
                Expr::Compare {
                    left: var("v"),
                    op,
                    right: text("1"),
                },
                "{src}"
            );
        }
    }

    #[test]
    fn operands_may_be_variables_strings_or_integers() {
        assert_eq!(
            ok("count == 3"),
            Expr::Compare {
                left: var("count"),
                op: RelOp::Eq,
                right: Operand::Int(3),
            }
        );
        // Double quotes read the same as single ones.
        assert_eq!(
            ok(r#"name == "nginx""#),
            Expr::Compare {
                left: var("name"),
                op: RelOp::Eq,
                right: text("nginx"),
            }
        );
    }

    #[test]
    fn precedence_is_not_over_and_over_or() {
        // `a and b or c` groups as `(a and b) or c`.
        let expr = ok("bound(a) and bound(b) or bound(c)");
        assert_eq!(
            expr,
            Expr::Or(
                Box::new(Expr::And(
                    Box::new(Expr::Bound("a".to_string())),
                    Box::new(Expr::Bound("b".to_string())),
                )),
                Box::new(Expr::Bound("c".to_string())),
            )
        );

        // `not a and b` groups as `(not a) and b`, not `not (a and b)`.
        let expr = ok("not matched and bound(v)");
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::Not(Box::new(Expr::Matched))),
                Box::new(Expr::Bound("v".to_string())),
            )
        );
    }

    #[test]
    fn parentheses_override_precedence() {
        // The parens force the `or` under the `and`.
        let expr = ok("bound(a) and (bound(b) or bound(c))");
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::Bound("a".to_string())),
                Box::new(Expr::Or(
                    Box::new(Expr::Bound("b".to_string())),
                    Box::new(Expr::Bound("c".to_string())),
                )),
            )
        );
    }

    #[test]
    fn the_grafana_guard_parses_as_written() {
        // The design's worked conditional-step guard, verbatim.
        let expr = ok("bound(version) and version < '8.3.1'");
        assert_eq!(
            expr,
            Expr::And(
                Box::new(Expr::Bound("version".to_string())),
                Box::new(Expr::Compare {
                    left: var("version"),
                    op: RelOp::Lt,
                    right: text("8.3.1"),
                }),
            )
        );
    }

    #[test]
    fn an_empty_or_whitespace_guard_is_rejected() {
        assert_eq!(parse(""), Err(ParseError::Empty));
        assert_eq!(parse("   "), Err(ParseError::Empty));
    }

    #[test]
    fn a_bare_operand_is_not_a_guard() {
        // No bare-value truthiness — a lone variable wants a comparison.
        assert_eq!(
            parse("version"),
            Err(ParseError::Expected("a comparison operator"))
        );
    }

    #[test]
    fn malformed_predicates_and_parens_are_rejected() {
        assert!(matches!(
            parse("bound version"),
            Err(ParseError::Expected(_))
        ));
        assert!(matches!(parse("bound()"), Err(ParseError::Expected(_))));
        assert!(matches!(parse("(matched"), Err(ParseError::Expected(_))));
        // A complete expression with leftover tokens.
        assert_eq!(parse("matched matched"), Err(ParseError::Trailing));
    }

    #[test]
    fn lexical_errors_name_their_cause() {
        assert_eq!(parse("v = '1'"), Err(ParseError::UnexpectedChar('=')));
        assert_eq!(parse("v & w"), Err(ParseError::UnexpectedChar('&')));
        assert_eq!(parse("v == 'open"), Err(ParseError::UnterminatedString));
        // An unquoted dotted version is not an integer and not a string, so its
        // stray '.' is the unexpected character — versions must be quoted.
        assert_eq!(parse("v < 8.3.1"), Err(ParseError::UnexpectedChar('.')));
    }
}

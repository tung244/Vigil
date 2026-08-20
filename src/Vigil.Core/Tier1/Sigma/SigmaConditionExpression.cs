namespace Vigil.Core.Tier1.Sigma;

/// <summary>
/// Sigma `condition` mini-language (subset): identifiers, and/or/not,
/// parentheses, "1 of them", "1 of pattern*", "all of them", "all of pattern*".
/// Parsed once at load time into an AST, then evaluated per event against
/// selection results.
/// </summary>
public abstract class SigmaConditionExpression
{
    public abstract bool Evaluate(Func<string, bool> selectionResult);

    /// <summary>Selection-name patterns this expression references (for validation).</summary>
    public abstract void CollectPatterns(List<string> patterns);

    public static SigmaConditionExpression Parse(string condition) =>
        new Parser(Tokenize(condition)).ParseExpression();

    // ── AST nodes ───────────────────────────────────────────────────────────

    private sealed class SelectionRef(string name) : SigmaConditionExpression
    {
        public override bool Evaluate(Func<string, bool> r) => r(name);
        public override void CollectPatterns(List<string> p) => p.Add(name);
    }

    private sealed class And(SigmaConditionExpression left, SigmaConditionExpression right)
        : SigmaConditionExpression
    {
        public SigmaConditionExpression Left { get; } = left;
        public SigmaConditionExpression Right { get; } = right;

        public override bool Evaluate(Func<string, bool> r) => Left.Evaluate(r) && Right.Evaluate(r);
        public override void CollectPatterns(List<string> p) { Left.CollectPatterns(p); Right.CollectPatterns(p); }
    }

    private sealed class Or(SigmaConditionExpression left, SigmaConditionExpression right)
        : SigmaConditionExpression
    {
        public SigmaConditionExpression Left { get; } = left;
        public SigmaConditionExpression Right { get; } = right;

        public override bool Evaluate(Func<string, bool> r) => Left.Evaluate(r) || Right.Evaluate(r);
        public override void CollectPatterns(List<string> p) { Left.CollectPatterns(p); Right.CollectPatterns(p); }
    }

    private sealed class Not(SigmaConditionExpression inner) : SigmaConditionExpression
    {
        public SigmaConditionExpression Inner { get; } = inner;

        public override bool Evaluate(Func<string, bool> r) => !Inner.Evaluate(r);
        public override void CollectPatterns(List<string> p) => Inner.CollectPatterns(p);
    }

    /// <summary>"1 of pattern" / "all of pattern" (pattern may be "them").</summary>
    private sealed class OfQuantifier(string pattern, bool requireAll) : SigmaConditionExpression
    {
        public override bool Evaluate(Func<string, bool> r)
        {
            // The engine resolves concrete selection names; here we delegate via
            // a synthetic call convention: r("of:" + pattern) is not used —
            // instead the engine pre-expands. See SigmaEngine.ExpandCondition.
            throw new InvalidOperationException("OfQuantifier must be expanded before evaluation.");
        }

        public override void CollectPatterns(List<string> p) => p.Add(requireAll ? $"all of {pattern}" : $"1 of {pattern}");

        public string Pattern => pattern;
        public bool RequireAll => requireAll;
    }

    /// <summary>Used by the engine to replace "x of pattern" with concrete refs.</summary>
    public static SigmaConditionExpression ExpandOfQuantifiers(
        SigmaConditionExpression expr, Func<string, IReadOnlyList<string>> resolvePattern)
    {
        switch (expr)
        {
            case OfQuantifier q:
                var names = resolvePattern(q.Pattern);
                if (names.Count == 0)
                {
                    // No selection matched the pattern — "1 of" is false, "all of" is vacuously true
                    // but Sigma treats it as false in practice; keep false for both.
                    return new Constant(false);
                }

                return names
                    .Select(n => (SigmaConditionExpression)new SelectionRef(n))
                    .Aggregate((acc, next) => q.RequireAll ? new And(acc, next) : new Or(acc, next));
            case And a:
                return new And(ExpandOfQuantifiers(a.Left, resolvePattern), ExpandOfQuantifiers(a.Right, resolvePattern));
            case Or o:
                return new Or(ExpandOfQuantifiers(o.Left, resolvePattern), ExpandOfQuantifiers(o.Right, resolvePattern));
            case Not n:
                return new Not(ExpandOfQuantifiers(n.Inner, resolvePattern));
            default:
                return expr;
        }
    }

    private sealed class Constant(bool value) : SigmaConditionExpression
    {
        public override bool Evaluate(Func<string, bool> _) => value;
        public override void CollectPatterns(List<string> _) { }
    }

    // ── Tokenizer + recursive-descent parser ────────────────────────────────

    private static List<string> Tokenize(string condition)
    {
        var tokens = new List<string>();
        var i = 0;
        while (i < condition.Length)
        {
            var c = condition[i];
            if (char.IsWhiteSpace(c))
            {
                i++;
            }
            else if (c is '(' or ')')
            {
                tokens.Add(c.ToString());
                i++;
            }
            else
            {
                var start = i;
                while (i < condition.Length && !char.IsWhiteSpace(condition[i]) && condition[i] is not '(' and not ')')
                {
                    i++;
                }

                tokens.Add(condition[start..i]);
            }
        }

        return tokens;
    }

    private sealed class Parser(List<string> tokens)
    {
        private int _pos;

        public SigmaConditionExpression ParseExpression()
        {
            var expr = ParseOr();
            if (_pos != tokens.Count)
            {
                throw new FormatException($"Unexpected token '{tokens[_pos]}' in Sigma condition.");
            }

            return expr;
        }

        private SigmaConditionExpression ParseOr()
        {
            var left = ParseAnd();
            while (Peek() is "or")
            {
                _pos++;
                left = new Or(left, ParseAnd());
            }

            return left;
        }

        private SigmaConditionExpression ParseAnd()
        {
            var left = ParseUnary();
            while (Peek() is "and")
            {
                _pos++;
                left = new And(left, ParseUnary());
            }

            return left;
        }

        private SigmaConditionExpression ParseUnary()
        {
            if (Peek() is "not")
            {
                _pos++;
                return new Not(ParseUnary());
            }

            return ParsePrimary();
        }

        private SigmaConditionExpression ParsePrimary()
        {
            var token = Next() ?? throw new FormatException("Unexpected end of Sigma condition.");

            if (token == "(")
            {
                var inner = ParseOr();
                if (Next() != ")")
                {
                    throw new FormatException("Missing ')' in Sigma condition.");
                }

                return inner;
            }

            // "1 of selection*" / "all of them"
            if (token is "1" or "all" && Peek() is "of")
            {
                _pos++; // consume "of"
                var pattern = Next() ?? throw new FormatException("Missing pattern after 'of' in Sigma condition.");
                return new OfQuantifier(pattern, requireAll: token == "all");
            }

            if (token is "and" or "or" or "of" or "them")
            {
                throw new FormatException($"Unexpected keyword '{token}' in Sigma condition.");
            }

            return new SelectionRef(token);
        }

        private string? Peek() => _pos < tokens.Count ? tokens[_pos] : null;

        private string? Next() => _pos < tokens.Count ? tokens[_pos++] : null;
    }
}

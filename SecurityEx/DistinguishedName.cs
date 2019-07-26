using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Woof.SecurityEx {

    /// <summary>
    /// RFC 4514 LDAP Distinguished Name implementation.
    /// </summary>
    public sealed class DistinguishedName {

        #region Properties

        /// <summary>
        /// Gets the common name part of the name.
        /// </summary>
        public string CN => this["CN"];

        /// <summary>
        /// Gets the domain component distinguished name.
        /// </summary>
        public DistinguishedName Domain => new DistinguishedName(Attributes.Where(i => i.Type.Equals("DC", DefaultStringComparison)));

        /// <summary>
        /// Gets a value indicating whether the distinguished name is empty (not set).
        /// </summary>
        public bool IsEmpty => Attributes == null || Attributes.Length < 1;

        /// <summary>
        /// Gets the parent container distinguished name.
        /// </summary>
        public DistinguishedName Parent => new DistinguishedName(Attributes.Skip(1));

        /// <summary>
        /// Gets the distinguished name attributes count.
        /// </summary>
        public int AttributesCount => Attributes.Length;

        /// <summary>
        /// Gets the distinguished name without domain.
        /// </summary>
        private DistinguishedName Path => new DistinguishedName(Attributes.Where(i => !i.Type.Equals("DC", DefaultStringComparison)));

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new distinguished name from a string value.
        /// If common name as plain text given, a distinguished name with CN attribute only is created.
        /// </summary>
        /// <param name="value">Valid distinguished name or empty.</param>
        public DistinguishedName(string value) {
            if (String.IsNullOrWhiteSpace(value)) return;
            if (value.Contains('=')) {
                OriginalString = value;
                Attributes = RxSplitParts.Split(value).Select(e => new Attribute(e.Replace("\\,", ","))).ToArray();
            } else {
                OriginalString = $"CN={value}";
                Attributes = new Attribute[] { new Attribute("CN", value) };
            }
        }

        /// <summary>
        /// Creates a derived distinguished name from parts collection.
        /// </summary>
        /// <param name="parts">Parts collection.</param>
        private DistinguishedName(IEnumerable<Attribute> parts) {
            if (parts != null) OriginalString = String.Join(",", (Attributes = parts.ToArray()).Select(i => i.ToString()));
        }

        #endregion

        #region Equality tests and replacement

        /// <summary>
        /// Returns hash code.
        /// </summary>
        /// <returns>Hash code.</returns>
        public override int GetHashCode() {
            int hc = Attributes.Length;
            for (int i = 0, n = hc; i < n; ++i) hc = unchecked(hc * 17 + Attributes[i].GetHashCode());
            return hc;
        }

        /// <summary>
        /// Determines whether this distinguished name is equivalent with the given one.
        /// </summary>
        /// <param name="obj">Object to test.</param>
        /// <returns>True if distinguished names are equivalent.</returns>
        public override bool Equals(object obj) =>
            obj is DistinguishedName dn
                ? dn.Attributes.SequenceEqual(Attributes)
                : (obj is string sn) ? ToString().Equals(sn, DefaultStringComparison) : false;

        /// <summary>
        /// Determines whether this distinguished name is equivalent with the given one.
        /// </summary>
        /// <param name="dn">Distinguished name to compare.</param>
        /// <returns>True if distinguished names are equivalent.</returns>
        public bool Equals(DistinguishedName dn) =>
            Attributes.All(a => a.Value == dn[a.Type]) &&
            (dn?.Attributes.All(a => a.Value == this[a.Type]) ?? false);

        /// <summary>
        /// Determines if string representation of this distinguised name is equivalent to given string.
        /// </summary>
        /// <param name="sn">String to compare.</param>
        /// <returns>True if distinguished names are equivalent.</returns>
        public bool Equals(string sn) => sn?.Equals(ToString(), DefaultStringComparison) ?? false;

        /// <summary>
        /// Tests whether 2 distinguished names are equivalent.
        /// </summary>
        /// <param name="dn1">First distinguished name.</param>
        /// <param name="dn2">Second distinguished name.</param>
        /// <returns>True if equivalent.</returns>
        public static bool operator ==(DistinguishedName dn1, DistinguishedName dn2)
            => (dn1 is null && dn2 is null) || (!(dn1 is null) && dn1.Equals(dn2));

        /// <summary>
        /// Tests whether 2 distinguished names are not equivalent.
        /// </summary>
        /// <param name="dn1">First distinguished name.</param>
        /// <param name="dn2">Second distinguished name.</param>
        /// <returns>True if NOT equivalent.</returns>
        public static bool operator !=(DistinguishedName dn1, DistinguishedName dn2)
            => (!(dn1 is null) || !(dn2 is null)) && (!(dn1 is null) && !dn1.Equals(dn2));



        /// <summary>
        /// Determines whether this distinguished name is a subtree of given distinguished name base.
        /// </summary>
        /// <param name="dn">Distinguished name base.</param>
        /// <returns>True if last elements match.</returns>
        public bool EndsWith(DistinguishedName dn) {
            if (dn == null) return false;
            var thisDomain = Domain;
            var thatDomain = dn.Domain;
            if (!thisDomain.Equals(thatDomain)) return false;
            var thatPath = dn.Path;
            if (thatPath.Attributes.Length < 1) return true;
            var thisPath = Path;
            return thisPath.Attributes.Length >= thatPath.Attributes.Length &&
                thisPath.Attributes.Skip(thisPath.Attributes.Length - thatPath.Attributes.Length)
                .SequenceEqual(thatPath.Attributes);
        }

        /// <summary>
        /// Determines whether this distinguished name is a subtree of given distinguished name base.
        /// </summary>
        /// <param name="sn">Distinguished name base as string.</param>
        /// <returns>True if last elements match.</returns>
        public bool EndsWith(string sn) => ToString().EndsWith(sn, DefaultStringComparison);

        /// <summary>
        /// Returns replacement base of that many replacement elements as search elements matching this distinguished name.
        /// </summary>
        /// <param name="search">Distinguished name to match.</param>
        /// <param name="replacement">Replacement distinguished name.</param>
        /// <returns>Replacement base.</returns>
        public DistinguishedName ReplacementBase(DistinguishedName search, DistinguishedName replacement) {
            var domains = new[] { Domain, search.Domain, replacement.Domain };
            var paths = new[] { Path, search.Path, replacement.Path };
            var stacks = Enumerable.Range(0, 4).Select(e => new Stack()).ToArray();
            for (int i = 0; i < 3; i++) foreach (var e in paths[i].Attributes) stacks[i].Push(e);
            for (int i = 0; i < 3; i++) if (!domains[i].IsEmpty) stacks[i].Push(null);
            var enumerators = stacks.Take(3).Select(e => e.GetEnumerator()).ToArray();
            while (enumerators.All(e => e.MoveNext())) {
                if (enumerators.All(e => e.Current is null))
                    foreach (var e in domains[2].Attributes.Reverse()) stacks[3].Push(e);
                else {
                    var parts = enumerators.Select(e => e.Current).ToArray();
                    if (parts.Length == 3 && parts[0].Equals(parts[1])) stacks[3].Push(parts[2]);
                    else break;
                }
            }
            return new DistinguishedName(stacks[3].OfType<Attribute>());
        }

        #endregion

        #region Conversions

        /// <summary>
        /// Returns the distinguished name as string.
        /// </summary>
        /// <returns></returns>
        public override string ToString() => OriginalString;

        /// <summary>
        /// Converts <see cref="DistinguishedName"/> to string implicitly.
        /// </summary>
        /// <param name="dn"></param>
        public static implicit operator String(DistinguishedName dn) => dn?.ToString();

        /// <summary>
        /// Converts <see cref="string"/> name to <see cref="DistinguishedName"/> implicitly.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator DistinguishedName(string value) => String.IsNullOrWhiteSpace(value) ? null : new DistinguishedName(value);

        #endregion

        #region Indexers

        /// <summary>
        /// Gets the part specified with short type descriptor.
        /// </summary>
        /// <param name="type">RFC 4512 short descriptor of the type.</param>
        /// <returns>Joined name part.</returns>
        public string this[string type] {
            get {
                if (Attributes == null || !Attributes.Any() || String.IsNullOrWhiteSpace(type)) return null;
                return type.Equals("DC", DefaultStringComparison)
                    ? String.Join(".", Attributes.Where(i => i.Type.Equals(type, DefaultStringComparison)).Select(i => i.Value))
                    : Attributes.FirstOrDefault(i => i.Type.Equals(type, DefaultStringComparison)).Value;
            }
        }

        #endregion

        /// <summary>
        /// RFC 4514 Distinguished Name Attribute.
        /// </summary>
        public sealed class Attribute {

            #region Properties

            /// <summary>
            /// Gets RFC 4512 short descriptor of the attribute type.
            /// </summary>
            public string Type { get; }

            /// <summary>
            /// Gets the attribute value.
            /// </summary>
            public string Value { get; }

            #endregion

            #region Constructors

            /// <summary>
            /// Creates RFC 4514 Distinguished Name Attribute.
            /// </summary>
            /// <param name="type">RFC 4512 short descriptor of the type.</param>
            /// <param name="value">Attribute value.</param>
            public Attribute(string type, string value) { Type = type; Value = value; }

            /// <summary>
            /// Creates RFC 4514 Distinguished Name Attribute.
            /// </summary>
            /// <param name="set">Type descriptor, "=" symbol and attribute value string.</param>
            public Attribute(string set) {
                if (String.IsNullOrWhiteSpace(set)) return;
                var parts = RxSplitSets.Split(set);
                if (parts.Length != 2) throw new InvalidOperationException("Not a RFC 4512 attribute and value string");
                Type = parts[0].Trim().ToUpper();
                Value = parts[1].Replace("\\=", "=").Trim();
            }

            #endregion

            #region Equality tests

            /// <summary>
            /// Tests whether the object is equivalent attribute with value.
            /// </summary>
            /// <param name="obj">An object to compare.</param>
            /// <returns>True if equivalent.</returns>
            public override bool Equals(object obj)
                => obj is Attribute a
                    ? a.Type.Equals(Type, DefaultStringComparison) && a.Value.Equals(Value, DefaultStringComparison)
                    : obj is String s ? Equals(new Attribute(s)) : false;

            /// <summary>
            /// Tests whether the attribute with value is equivalent to the given one.
            /// </summary>
            /// <param name="a">An attribute with value.</param>
            /// <returns>True if equivalent.</returns>
            bool Equals(Attribute a) => a.Type.Equals(Type, DefaultStringComparison) && a.Value.Equals(Value, DefaultStringComparison);

            /// <summary>
            /// Calculates hash code.
            /// </summary>
            /// <returns></returns>
            public override int GetHashCode() => 2 * Type.GetHashCode() + Value.GetHashCode();

            /// <summary>
            /// Returns attribute with value string representation.
            /// </summary>
            /// <returns></returns>
            public override string ToString() => $"{Type}={Value}";

            /// <summary>
            /// Converts <see cref="Attribute"/> to string implicitly.
            /// </summary>
            /// <param name="attribute"></param>
            public static implicit operator String(Attribute attribute) => attribute?.ToString();

            /// <summary>
            /// Converts <see cref="string"/> to <see cref="Attribute"/> implicitly.
            /// </summary>
            /// <param name="value"></param>
            public static implicit operator Attribute(string value) => String.IsNullOrWhiteSpace(value) ? null : new Attribute(value);

            /// <summary>
            /// Tests whether 2 attributes are equivalent.
            /// </summary>
            /// <param name="a1">First attribute.</param>
            /// <param name="a2">Second attribute.</param>
            /// <returns></returns>
            public static bool operator ==(Attribute a1, Attribute a2)
                => (a1 is null && a2 is null) || (!(a1 is null) && a1.Equals(a2));

            /// <summary>
            /// Tests whether 2 attributes are NOT equivalent.
            /// </summary>
            /// <param name="a1">First attribute.</param>
            /// <param name="a2">Second attribute.</param>
            /// <returns></returns>
            public static bool operator !=(Attribute a1, Attribute a2)
                => (!(a1 is null) || !(a2 != null) && !(a1 is null) && !a1.Equals(a2));

            #endregion

            /// <summary>
            /// Default comparison mode for type descriptor and value strings.
            /// </summary>
            const StringComparison DefaultStringComparison = StringComparison.OrdinalIgnoreCase;

        }

        #region Public data

        /// <summary>
        /// Gets the parts of the distinguised name.
        /// </summary>
        public readonly Attribute[] Attributes;

        /// <summary>
        /// A string used to build distinguished name.
        /// </summary>
        public readonly string OriginalString;

        #endregion

        #region Private data


        /// <summary>
        /// Default comparison mode for key and value strings.
        /// </summary>
        const StringComparison DefaultStringComparison = StringComparison.OrdinalIgnoreCase;

        /// <summary>
        /// Splits by unescaped coma.
        /// </summary>
        private static readonly Regex RxSplitParts = new Regex(@"(?<!\\),", RegexOptions.Compiled);

        /// <summary>
        /// Splits by unescaped equals.
        /// </summary>
        private static readonly Regex RxSplitSets = new Regex(@"(?<!\\)=", RegexOptions.Compiled);

        #endregion

    }

}

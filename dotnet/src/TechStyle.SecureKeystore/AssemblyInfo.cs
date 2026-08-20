using System.Runtime.CompilerServices;

// The tests reach into LegacyGcm and Crypto directly. That is deliberate: the
// hand-written GCM is the one piece of this library that must be checked against
// the platform's own implementation, and that check cannot be written through
// the public surface.
[assembly: InternalsVisibleTo("TechStyle.SecureKeystore.Tests")]

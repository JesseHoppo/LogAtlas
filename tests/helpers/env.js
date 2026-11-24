// Wall clocks parsed without a zone are anchored to UTC by the app, but the
// few strings that fall through to the native parser read in the host's zone.
// Pinning it keeps every machine's run identical. Import this first.
process.env.TZ = 'UTC';

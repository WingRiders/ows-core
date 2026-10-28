// midnight-js 5's indexer provider require()s graphql; load it before any
// top-level await makes the module graph async (same as the playground).
import "graphql";

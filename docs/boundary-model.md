# Boundary Model

The project treats every transfer as a boundary crossing:

```text
producer runtime -> transfer envelope -> consumer runtime
```

The boundary is interesting because producer and consumer may disagree about:

- whether data is trusted;
- what action was approved;
- whether the context is fresh;
- whether a tool result is observation or instruction;
- whether authority should travel with data.

The verifier therefore checks the envelope before the consumer treats the
payload as usable context.

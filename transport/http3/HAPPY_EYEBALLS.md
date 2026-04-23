# Happy Eyeballs Implementation (RFC 8305)

This document describes the Happy Eyeballs implementation in `dial_he.go`, which provides dual-stack IPv4/IPv6 connection handling for the HTTP3 transport layer.

## Overview

Happy Eyeballs (RFC 8305) is an algorithm that improves connection reliability and performance in dual-stack environments by:

1. Resolving both IPv4 and IPv6 addresses for a hostname
2. Attempting connections in parallel with staggered delays
3. Returning the first successful connection
4. Canceling remaining attempts once one succeeds

## Implementation

### Files

- **`dial_he.go`**: Core implementation with `resolveTargets` and `happyEyeballsDial` functions
- **`dial_he_test.go`**: Comprehensive unit tests covering all scenarios
- **`dial_he_example.go`**: Example integration code (build-ignored)

### Key Functions

#### `resolveTargets(ctx, hostport, prefer) ([]target, error)`

Resolves a host:port string into a list of dialable targets.

**Parameters:**
- `ctx`: Context for cancellation
- `hostport`: Address in "host:port" format
- `prefer`: Address family preference
  - `"auto"`: IPv6 first (RFC 6724), then IPv4
  - `"v4"`: IPv4 only
  - `"v6"`: IPv6 only

**Returns:**
- List of targets ordered by preference
- Error if resolution fails

**Features:**
- Handles both IP addresses and hostnames
- Performs DNS resolution with context support
- Separates IPv4 and IPv6 addresses
- Orders results according to preference
- Validates preference against resolved addresses

#### `happyEyeballsDial(ctx, targets, delay, dialOne) (interface{}, error)`

Implements the Happy Eyeballs algorithm for parallel connection attempts.

**Parameters:**
- `ctx`: Context for cancellation
- `targets`: List of targets to dial (ordered by preference)
- `delay`: Stagger delay between attempts (typically 50-300ms)
- `dialOne`: Function to dial a single target

**Returns:**
- First successful connection
- Error if all attempts fail

**Features:**
- Launches dial attempts with staggered delays
- First attempt starts immediately
- Subsequent attempts delayed by `delay * index`
- Cancels all in-flight attempts on first success
- Properly handles context cancellation
- Thread-safe with goroutine coordination

### Data Structures

#### `target`

Represents a resolved address that can be dialed.

```go
type target struct {
    network string       // "udp4" or "udp6"
    addr    *net.UDPAddr // resolved UDP address
}
```

#### `dialResult`

Internal structure for collecting dial results from goroutines.

```go
type dialResult struct {
    conn   interface{} // Connection (generic type)
    target target      // The target that was dialed
    err    error       // Error if dial failed
}
```

## Testing

The implementation includes comprehensive unit tests covering:

### `resolveTargets` Tests

1. **IP Address Resolution**
   - IPv4 addresses with different preferences
   - IPv6 addresses with different preferences
   - Preference validation (v4 with IPv6 address should fail)

2. **Hostname Resolution**
   - localhost resolution with different preferences
   - DNS resolution with context support
   - Address ordering verification

3. **Error Handling**
   - Invalid hostport format
   - Invalid preference values
   - Context cancellation during DNS lookup

### `happyEyeballsDial` Tests

1. **Single Target**
   - Basic dial with one target
   - Success and failure cases

2. **Multiple Targets**
   - First target succeeds immediately
   - First target fails, second succeeds
   - All targets fail

3. **Timing and Stagger**
   - Verify stagger delays are applied correctly
   - First attempt is immediate
   - Subsequent attempts delayed by `delay * index`

4. **Concurrency**
   - Race condition testing with many targets
   - Proper goroutine cancellation
   - Thread-safety verification

5. **Context Handling**
   - Parent context cancellation
   - Child context cancellation on success
   - Timeout handling

## Integration

### Current Status

The Happy Eyeballs implementation is **ready for integration** into `Factory.Dial` in `client.go`.

### Integration Steps

1. **Add configuration option** in `option/config.go`:
   ```go
   PreferAddressFamily string        // "auto", "v4", or "v6"
   HappyEyeballsDelay  time.Duration // default 50ms
   ```

2. **Modify `Factory.Dial`** to use Happy Eyeballs:
   ```go
   // Resolve targets
   targets, err := resolveTargets(ctx, target.Addr, f.opts.PreferAddressFamily)
   if err != nil {
       return nil, err
   }
   
   // Define dialOne function
   dialOne := func(ctx context.Context, t target) (interface{}, error) {
       transport, err := f.pool.Get(ctx, t.network, "", f.bypass)
       if err != nil {
           return nil, err
       }
       return transport.Dial(ctx, t.addr, tlsCfg, quicCfg)
   }
   
   // Use Happy Eyeballs
   conn, err := happyEyeballsDial(ctx, targets, f.opts.HappyEyeballsDelay, dialOne)
   ```

3. **Wrap in ECH retry loop** as needed for the existing ECH handling logic.

### Shared with IPv6 Spec

This implementation is designed to be shared between:
- **Performance Optimization Spec** (Task 3.3)
- **IPv6 Connectivity Spec** (Windows IPv6 fixes)

Both specs benefit from the same Happy Eyeballs logic for improved connection reliability.

## RFC 8305 Compliance

The implementation follows RFC 8305 recommendations:

- ✅ Parallel connection attempts with staggered delays
- ✅ IPv6 preference in "auto" mode (RFC 6724)
- ✅ Configurable stagger delay (50-300ms recommended)
- ✅ First successful connection wins
- ✅ Cancellation of remaining attempts
- ✅ Proper error handling and reporting

**Simplified aspects:**
- Does not implement connection attempt sorting beyond IPv4/IPv6 separation
- Does not implement destination address selection algorithm (relies on OS)
- Stagger delay is fixed per attempt (not adaptive)

These simplifications are acceptable for the use case and can be enhanced later if needed.

## Performance Characteristics

- **Memory**: O(n) where n is the number of resolved addresses
- **Goroutines**: One per target (typically 1-4)
- **Latency**: 
  - Best case: Same as single dial (first succeeds)
  - Worst case: `delay * (n-1)` + slowest dial time
  - Typical: 50-100ms improvement over sequential attempts

## Future Enhancements

Potential improvements for future iterations:

1. **Adaptive delay**: Adjust stagger delay based on network conditions
2. **Connection caching**: Cache successful address families per hostname
3. **Metrics**: Track success rates per address family
4. **Advanced sorting**: Implement full RFC 6724 destination address selection
5. **Connection racing**: Start all attempts simultaneously (more aggressive)

## References

- [RFC 8305: Happy Eyeballs Version 2](https://www.rfc-editor.org/rfc/rfc8305.html)
- [RFC 6724: Default Address Selection for IPv6](https://www.rfc-editor.org/rfc/rfc6724.html)

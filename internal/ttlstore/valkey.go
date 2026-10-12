// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package ttlstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

const DefaultCommandTimeout = 5 * time.Second
const valkeyNamespace = "{dnscheck:ttl:v2}:"

// ValkeyClient stores versioned values and a bounded quota ledger. All keys use
// the same hash tag, so conditions and mutations are atomic across processes
// and supported in a single Valkey Cluster slot. Use noeviction: independently
// evicting ledger or data keys invalidates storage accounting.
// Zero-valued limits are finite defaults. All clients sharing a namespace must
// have the same limits. Legacy upstream hash/HSETEX data is not this format.
type ValkeyClient struct {
	valkey.Client
	CommandTimeout  time.Duration
	MaxSize         int
	MaxBytes        int
	MaxValuesPerKey int
	MaxValueBytes   int
}

func (c *ValkeyClient) ctx() (context.Context, context.CancelFunc) {
	timeout := c.CommandTimeout
	if timeout == 0 {
		timeout = DefaultCommandTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}
func (c *ValkeyClient) limits() limits {
	return normalizedLimits(c.MaxSize, c.MaxBytes, c.MaxValuesPerKey, c.MaxValueBytes)
}
func physicalKey(key string) string { return valkeyNamespace + "data:" + key }

// CheckConfiguration is a read-only startup check. A dedicated database and
// noeviction keep legacy records from being silently ignored and prevent the
// server from independently evicting quota metadata. The service account needs
// permission for CONFIG GET maxmemory-policy and SCAN. Cluster deployments
// must use a dedicated cluster; every node must keep the same eviction policy.
func (c *ValkeyClient) CheckConfiguration() error {
	ctx, done := c.ctx()
	defer done()
	for _, node := range c.Nodes() {
		configuration, err := node.Do(ctx, node.B().ConfigGet().Parameter("maxmemory-policy").Build()).AsStrMap()
		if err != nil {
			return fmt.Errorf("cannot verify Valkey noeviction policy: %w", err)
		}
		if configuration["maxmemory-policy"] != "noeviction" {
			return fmt.Errorf("Valkey maxmemory-policy must be noeviction to preserve atomic quota accounting")
		}
		var page valkey.ScanEntry
		for {
			page, err = node.Do(ctx, node.B().Scan().Cursor(page.Cursor).Count(1000).Build()).AsScanEntry()
			if err != nil {
				return err
			}
			for _, key := range page.Elements {
				if !strings.HasPrefix(key, valkeyNamespace) {
					return fmt.Errorf("%w: Valkey requires a dedicated version 2 database", ErrLegacyFormat)
				}
			}
			if page.Cursor == 0 {
				break
			}
		}
	}
	return nil
}

// This script only starts writing after all conditions, schemas, quota limits,
// command key types, and JSON encodings have been checked. Lua scripts provide
// isolation, not rollback after a script error, so validation belongs first.
// Expired ledger entries may conservatively reserve quota until a successful
// operation or Prune removes them; reclamation work is bounded to 256 keys.
var applyScript = valkey.NewLuaScript(`
local input = cjson.decode(ARGV[1])
local now = tonumber(redis.call('TIME')[1])
local usage, expiry = KEYS[1], KEYS[2]
local oldCount = tonumber(redis.call('HGET', usage, '@count') or '0')
local oldBytes = tonumber(redis.call('HGET', usage, '@bytes') or '0')
local version = redis.call('HGET', usage, '@version')
if (version and version ~= '2') or not oldCount or not oldBytes or oldCount < 0 or oldBytes < 0 then
 return redis.error_reply('DNSCHECK invalid quota schema')
end
local expired = redis.call('ZRANGEBYSCORE', expiry, '-inf', now, 'LIMIT', 0, 256)
local expiredSet, count, size = {}, oldCount, oldBytes
for _, key in ipairs(expired) do
 expiredSet[key] = true
 local weight = redis.call('HGET', usage, key)
 if weight then
  local w = cjson.decode(weight)
  if type(w.n) ~= 'number' or type(w.b) ~= 'number' or w.n < 0 or w.b < 0 then return redis.error_reply('DNSCHECK invalid quota weight') end
  count = count - w.n; size = size - w.b
 end
end
local states, weights = {}, {}
for i = 3, #KEYS do
 local raw = redis.call('GET', KEYS[i])
 local state = {}
 if raw then
  local object = cjson.decode(raw)
  if object.version ~= 2 or type(object.values) ~= 'table' then return redis.error_reply('DNSCHECK unsupported data schema') end
  for _, value in ipairs(object.values) do
   if type(value.Expires) ~= 'number' or type(value.Value) ~= 'string' then return redis.error_reply('DNSCHECK invalid data schema') end
   if value.Expires > now then table.insert(state, value) end
  end
 end
 states[i] = state
 local weight = redis.call('HGET', usage, KEYS[i])
 if raw and (not version or not weight) then return redis.error_reply('DNSCHECK missing quota ledger; restore or migrate data') end
 if weight and not expiredSet[KEYS[i]] then
  local w = cjson.decode(weight)
  if type(w.n) ~= 'number' or type(w.b) ~= 'number' or w.n < 0 or w.b < 0 then return redis.error_reply('DNSCHECK invalid quota weight') end
  weights[i] = w
 else weights[i] = {n=0,b=0} end
end
for _, check in ipairs(input.checks) do
 local state = states[check.i]
 if check.absent then
  if #state ~= 0 then return 0 end
 elseif #state ~= 1 or state[1].Value ~= check.value then return 0 end
end
local changed = {}
for _, op in ipairs(input.ops) do
 local state = states[op.i]
 if op.kind == 'delete' then state = {}
 elseif op.kind == 'set' then state = {{Expires=now+op.ttl,Value=op.value}}
 elseif op.kind == 'add' then
  local found = false
  for _, v in ipairs(state) do if v.Value == op.value then v.Expires=now+op.ttl; found=true; break end end
  if not found then table.insert(state,{Expires=now+op.ttl,Value=op.value}) end
 elseif op.kind == 'remove' then
  local keep = {}
  for _, v in ipairs(state) do if v.Value ~= op.value then table.insert(keep,v) end end
  state = keep
 else return redis.error_reply('DNSCHECK invalid operation') end
 local cap = input.limits.MaxValuesPerKey
 if op.maxValues > 0 and op.maxValues < cap then cap = op.maxValues end
 if #state > cap then return 2 end
 states[op.i] = state
 changed[op.i] = op.keyBytes
end
local encoded, newWeights, ttls = {}, {}, {}
for i,keyBytes in pairs(changed) do
 local n,b,last = #states[i],0,now
 for _, v in ipairs(states[i]) do
  local encodedLength = #v.Value
  local pad = 0
  if string.sub(v.Value,-2) == '==' then pad=2 elseif string.sub(v.Value,-1)=='=' then pad=1 end
  local valueBytes = encodedLength*3/4-pad
  if encodedLength % 4 ~= 0 or valueBytes > input.limits.MaxValueBytes then return redis.error_reply('DNSCHECK invalid value size') end
  b=b+keyBytes+valueBytes
  if v.Expires>last then last=v.Expires end
 end
 count=count+n-weights[i].n; size=size+b-weights[i].b
 newWeights[i]=cjson.encode({n=n,b=b})
 encoded[i]=cjson.encode({version=2,values=states[i]})
 ttls[i]=last-now
end
if count < 0 or size < 0 then return redis.error_reply('DNSCHECK inconsistent quota ledger') end
if count > input.limits.MaxSize or size > input.limits.MaxBytes then return 2 end
-- Every possibly failing schema/quota/encoding step is above this line.
for _,key in ipairs(expired) do redis.call('HDEL',usage,key); redis.call('ZREM',expiry,key) end
for i,_ in pairs(changed) do
 if #states[i] == 0 then
  redis.call('DEL',KEYS[i]); redis.call('HDEL',usage,KEYS[i]); redis.call('ZREM',expiry,KEYS[i])
 else
  redis.call('SET',KEYS[i],encoded[i],'EX',ttls[i])
  redis.call('HSET',usage,KEYS[i],newWeights[i])
  redis.call('ZADD',expiry,now+ttls[i],KEYS[i])
 end
end
redis.call('HSET',usage,'@version','2','@count',count,'@bytes',size)
return 1
`)

type scriptCheck struct {
	Index  int    `json:"i"`
	Absent bool   `json:"absent"`
	Value  string `json:"value"`
}
type scriptOp struct {
	Index     int          `json:"i"`
	Kind      MutationKind `json:"kind"`
	Value     string       `json:"value"`
	TTL       uint32       `json:"ttl"`
	MaxValues int          `json:"maxValues"`
	KeyBytes  int          `json:"keyBytes"`
}

func (c *ValkeyClient) Apply(checks []Condition, ops []Mutation) (bool, error) {
	lim := c.limits()
	if err := validateBatch(checks, ops, lim); err != nil {
		return false, err
	}
	keys := []string{valkeyNamespace + "usage", valkeyNamespace + "expiry"}
	indices := make(map[string]int)
	index := func(key string) int {
		if i, ok := indices[key]; ok {
			return i
		}
		keys = append(keys, physicalKey(key))
		indices[key] = len(keys)
		return len(keys)
	}
	input := struct {
		Checks []scriptCheck `json:"checks"`
		Ops    []scriptOp    `json:"ops"`
		Limits limits        `json:"limits"`
	}{Checks: make([]scriptCheck, 0, len(checks)), Ops: make([]scriptOp, 0, len(ops)), Limits: lim}
	for _, check := range checks {
		input.Checks = append(input.Checks, scriptCheck{index(check.Key), check.Value == nil, base64.StdEncoding.EncodeToString(check.Value)})
	}
	for _, op := range ops {
		input.Ops = append(input.Ops, scriptOp{index(op.Key), op.Kind, base64.StdEncoding.EncodeToString(op.Value), op.TTL, op.MaxValues, len(op.Key)})
	}
	data, err := json.Marshal(input)
	if err != nil {
		return false, err
	}
	ctx, done := c.ctx()
	defer done()
	result, err := applyScript.Exec(ctx, c.Client, keys, []string{string(data)}).AsInt64()
	if err != nil {
		return false, err
	}
	switch result {
	case 0:
		return false, nil
	case 1:
		return true, nil
	case 2:
		return false, ErrCapacity
	default:
		return false, fmt.Errorf("invalid atomic store response")
	}
}
func (c *ValkeyClient) Add(key string, val []byte, ttl uint32) error {
	_, err := c.Apply(nil, []Mutation{{Kind: AddValue, Key: key, Value: val, TTL: ttl}})
	return err
}
func (c *ValkeyClient) Set(key string, val []byte, ttl uint32) error {
	_, err := c.Apply(nil, []Mutation{{Kind: SetValue, Key: key, Value: val, TTL: ttl}})
	return err
}
func (c *ValkeyClient) Remove(key string, val []byte) error {
	_, err := c.Apply(nil, []Mutation{{Kind: RemoveValue, Key: key, Value: val}})
	return err
}
func (c *ValkeyClient) Delete(key string) error {
	_, err := c.Apply(nil, []Mutation{{Kind: DeleteKey, Key: key}})
	return err
}

// Prune performs bounded quota reclamation without changing live application data.
func (c *ValkeyClient) Prune() error { _, err := c.Apply(nil, nil); return err }

var valuesScript = valkey.NewLuaScriptReadOnly(`
local raw=redis.call('GET',KEYS[1])
if not raw then return {} end
local state=cjson.decode(raw)
if state.version~=2 or type(state.values)~='table' then return redis.error_reply('DNSCHECK unsupported data schema') end
local now=tonumber(redis.call('TIME')[1])
local out={}
for _,value in ipairs(state.values) do
 if type(value.Expires)~='number' or type(value.Value)~='string' then return redis.error_reply('DNSCHECK invalid data schema') end
 if value.Expires>now then table.insert(out,value.Value) end
end
return out
`)

func (c *ValkeyClient) Values(key string) ([][]byte, error) {
	if len(key) == 0 || len(key) > MaxKeyBytes {
		return nil, ErrInvalidOperation
	}
	ctx, done := c.ctx()
	defer done()
	values, err := valuesScript.Exec(ctx, c.Client, []string{physicalKey(key)}, nil).AsStrSlice()
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(values))
	for _, v := range values {
		b, err := base64.StdEncoding.Strict().DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid store value: %w", err)
		}
		out = append(out, b)
	}
	return out, nil
}
func (c *ValkeyClient) Get(key string) ([]byte, error) {
	vals, err := c.Values(key)
	if err != nil || len(vals) == 0 {
		return nil, err
	}
	return vals[0], nil
}
func (c *ValkeyClient) Exists(key string) (bool, error) {
	vals, err := c.Values(key)
	return len(vals) > 0, err
}
func escapeGlob(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`).Replace(s)
}
func (c *ValkeyClient) List(prefix string) ([]string, error) {
	ctx, done := c.ctx()
	defer done()
	seen := make(map[string]struct{})
	base := physicalKey("")
	// SCAN is node-local. Visit known nodes so a cluster's selected hash slot
	// is not accidentally omitted; replicas/scan repeats are deduplicated.
	for _, node := range c.Nodes() {
		var page valkey.ScanEntry
		for {
			var err error
			page, err = node.Do(ctx, node.B().Scan().Cursor(page.Cursor).Match(escapeGlob(base+prefix)+"*").Count(100).Build()).AsScanEntry()
			if err != nil {
				return nil, err
			}
			for _, key := range page.Elements {
				seen[strings.TrimPrefix(key, base)] = struct{}{}
			}
			if page.Cursor == 0 {
				break
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

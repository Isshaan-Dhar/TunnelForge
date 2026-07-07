package redis

import (
	"context"
	"time"

	redisclient "github.com/redis/go-redis/v9"
)

type Store struct {
	client *redisclient.Client
}

var rateLimitScript = redisclient.NewScript(`
	local current
	current = redis.call("incr", KEYS[1])
	if current == 1 then
		redis.call("expire", KEYS[1], ARGV[1])
	end
	return current
`)

func New(addr string) (*Store, error) {
	client := redisclient.NewClient(&redisclient.Options{
		Addr: addr,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}
	return &Store{client: client}, nil
}

func (s *Store) Close() error {
	return s.client.Close()
}

func (s *Store) BlacklistToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	return s.client.Set(ctx, "blacklist:"+tokenID, "1", ttl).Err()
}

func (s *Store) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	exists, err := s.client.Exists(ctx, "blacklist:"+tokenID).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (s *Store) IncrementRateLimit(ctx context.Context, key string, window time.Duration) (int64, error) {
	return rateLimitScript.Run(ctx, s.client, []string{key}, int(window.Seconds())).Int64()
}

package redis

import (
	"context"
	"time"

	redisclient "github.com/redis/go-redis/v9"
)

type Store struct {
	client *redisclient.Client
}

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
	pipe := s.client.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

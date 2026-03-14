package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store struct {
	client *redis.Client
}

func New(addr string) (*Store, error) {
	client := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
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
	n, err := s.client.Exists(ctx, "blacklist:"+tokenID).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

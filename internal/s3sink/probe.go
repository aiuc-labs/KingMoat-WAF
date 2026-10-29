// Read-only probe support for the console outbound-channel test endpoint.
// This file deliberately adds ONE exported helper on top of the shipping
// client constructor; nothing in it writes to the bucket.
package s3sink

import (
	"context"
	"fmt"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/kingmoat/kingmoat/internal/config"
)

// ProbeBucket verifies the S3 credentials and bucket access with two
// read-only calls: HEAD bucket (BucketExists) first, and — when the store
// rejects the HEAD — one MaxKeys=1 ListObjectsV2 retry (compat stores
// commonly deny unauthorized HEADs while the credentials themselves work).
// Returns (true, nil) when the bucket is usable with these credentials,
// (false, nil) when the store authoritatively reports NoSuchBucket, and
// (false, err) with the terminal error otherwise for the caller to classify
// (auth failure vs. server error vs. unreachable).
func ProbeBucket(ctx context.Context, cfg *config.S3Settings, region string) (bool, error) {
	if cfg == nil {
		return false, fmt.Errorf("s3: settings required")
	}
	mc, err := minio.New(strings.TrimSpace(cfg.Endpoint), &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: region,
	})
	if err != nil {
		return false, err
	}
	ok, err := mc.BucketExists(ctx, cfg.Bucket)
	if err == nil {
		return ok, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	// HEAD was rejected: re-check once with a single-object listing.
	for obj := range mc.ListObjectsIter(ctx, cfg.Bucket, minio.ListObjectsOptions{MaxKeys: 1}) {
		if obj.Err != nil {
			return false, obj.Err
		}
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	// The listing request itself succeeded on an empty bucket.
	return true, nil
}

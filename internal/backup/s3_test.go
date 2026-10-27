package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"testing"

	"rgstr/internal/config"
)

// TestS3 runs against a real S3-compatible store when RGSTR_TEST_S3 is set,
// e.g. MinIO:
//
//	docker run -d -p 9000:9000 minio/minio server /data
//	RGSTR_TEST_S3=http://localhost:9000 go test ./internal/backup -run S3
//
// (bucket "rgstr-test", keys minioadmin/minioadmin unless overridden).
func TestS3(t *testing.T) {
	endpoint := os.Getenv("RGSTR_TEST_S3")
	if endpoint == "" {
		t.Skip("RGSTR_TEST_S3 not set")
	}
	key := envOr("RGSTR_TEST_S3_KEY", "minioadmin")
	secret := envOr("RGSTR_TEST_S3_SECRET", "minioadmin")
	tg, err := NewTarget(config.BackupConfig{Target: "s3://" + envOr("RGSTR_TEST_S3_BUCKET", "rgstr-test") + "/ci",
		S3: config.S3Config{Endpoint: endpoint, Region: "us-east-1", AccessKey: key, SecretKey: secret, PathStyle: true}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	data := make([]byte, minPartSize+5<<20) // two parts
	rand.Read(data)
	name := "rgstr-backup-20261027-030000.tar"
	if err := tg.Put(ctx, name, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	objs, err := List(ctx, tg)
	if err != nil || len(objs) == 0 || objs[len(objs)-1].Size != int64(len(data)) {
		t.Fatalf("list: %+v %v", objs, err)
	}
	rc, err := tg.Get(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded data differs")
	}
	if err := tg.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	bad, _ := NewTarget(config.BackupConfig{Target: "s3://rgstr-test/ci",
		S3: config.S3Config{Endpoint: endpoint, Region: "us-east-1", AccessKey: key, SecretKey: "wrong", PathStyle: true}})
	if _, err := List(ctx, bad); err == nil {
		t.Error("wrong secret accepted")
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

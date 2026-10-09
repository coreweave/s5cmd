package e2e

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

func TestSafeStorageErrorCode(t *testing.T) {
	for _, code := range []string{"TooManyBuckets", "InvalidRegion", "AccessDenied"} {
		if got := safeStorageErrorCode(code); got != code {
			t.Fatalf("public storage code %q was suppressed", code)
		}
	}
	for _, code := range []string{"synthetic-private-value", "TooManyBuckets synthetic-private-value", ""} {
		if got := safeStorageErrorCode(code); got != "storage request failed" {
			t.Fatal("unknown storage code was disclosed")
		}
	}
}

type cleanupFixture struct {
	s3iface.S3API
	fail                      string
	bucket                    string
	aborted, deleted, batches int
	removed                   bool
}

func (f *cleanupFixture) check(bucket *string, stage string) error {
	if aws.StringValue(bucket) != f.bucket {
		return errors.New("cleanup escaped its bucket")
	}
	if f.fail == stage {
		return errors.New("synthetic-private-value")
	}
	return nil
}
func (f *cleanupFixture) HeadBucketWithContext(_ aws.Context, in *s3.HeadBucketInput, _ ...request.Option) (*s3.HeadBucketOutput, error) {
	if f.fail == "absent" {
		return nil, awserr.NewRequestFailure(awserr.New("NoSuchBucket", "missing", nil), 404, "synthetic")
	}
	return &s3.HeadBucketOutput{}, f.check(in.Bucket, "head")
}
func (f *cleanupFixture) ListMultipartUploadsPagesWithContext(_ aws.Context, in *s3.ListMultipartUploadsInput, page func(*s3.ListMultipartUploadsOutput, bool) bool, _ ...request.Option) error {
	if err := f.check(in.Bucket, "uploads"); err != nil {
		return err
	}
	page(&s3.ListMultipartUploadsOutput{Uploads: []*s3.MultipartUpload{{Key: aws.String("unfinished"), UploadId: aws.String("upload")}}}, true)
	return nil
}
func (f *cleanupFixture) AbortMultipartUploadWithContext(_ aws.Context, in *s3.AbortMultipartUploadInput, _ ...request.Option) (*s3.AbortMultipartUploadOutput, error) {
	f.aborted++
	return &s3.AbortMultipartUploadOutput{}, f.check(in.Bucket, "abort")
}
func (f *cleanupFixture) ListObjectVersionsPagesWithContext(_ aws.Context, in *s3.ListObjectVersionsInput, page func(*s3.ListObjectVersionsOutput, bool) bool, _ ...request.Option) error {
	if err := f.check(in.Bucket, "versions"); err != nil {
		return err
	}
	output := &s3.ListObjectVersionsOutput{}
	for n := 0; n < 1001; n++ {
		output.Versions = append(output.Versions, &s3.ObjectVersion{Key: aws.String("object"), VersionId: aws.String("version")})
	}
	page(output, false)
	page(&s3.ListObjectVersionsOutput{DeleteMarkers: []*s3.DeleteMarkerEntry{{Key: aws.String("deleted"), VersionId: aws.String("marker")}}}, true)
	return nil
}
func (f *cleanupFixture) DeleteObjectsWithContext(_ aws.Context, in *s3.DeleteObjectsInput, _ ...request.Option) (*s3.DeleteObjectsOutput, error) {
	f.batches++
	f.deleted += len(in.Delete.Objects)
	if f.fail == "partial delete" {
		return &s3.DeleteObjectsOutput{Errors: []*s3.Error{{Code: aws.String("AccessDenied")}}}, nil
	}
	return &s3.DeleteObjectsOutput{}, f.check(in.Bucket, "delete")
}
func (f *cleanupFixture) DeleteBucketWithContext(_ aws.Context, in *s3.DeleteBucketInput, _ ...request.Option) (*s3.DeleteBucketOutput, error) {
	if err := f.check(in.Bucket, "bucket"); err != nil {
		return nil, err
	}
	f.removed = true
	return &s3.DeleteBucketOutput{}, nil
}
func TestAcceptanceCleanup(t *testing.T) {
	const bucket = "s5cmd-acceptance-0123456789abcdef01234567"
	for _, stage := range []string{"success", "absent", "head", "uploads", "abort", "versions", "delete", "partial delete", "bucket"} {
		t.Run(stage, func(t *testing.T) {
			fixture := &cleanupFixture{fail: stage, bucket: bucket}
			err := cleanAcceptanceBucket(context.Background(), fixture, bucket)
			if stage == "success" {
				if err != nil || !fixture.removed || fixture.aborted != 1 || fixture.deleted != 1002 || fixture.batches != 2 {
					t.Fatal("cleanup omitted resources or exceeded batch size")
				}
			} else if stage == "absent" {
				if err != nil || fixture.removed {
					t.Fatal("absent bucket cleanup changed")
				}
			} else if err == nil {
				t.Fatal("cleanup failure must fail the suite")
			}
			if err != nil && err.Error() == "synthetic-private-value" {
				t.Fatal("cleanup exposed service diagnostics")
			}
		})
	}
	if err := cleanAcceptanceBucket(context.Background(), &cleanupFixture{}, "another-run"); err == nil {
		t.Fatal("invalid cleanup scope accepted")
	}
}

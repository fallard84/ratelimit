package ratelimit

import (
	"testing"

	ratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/envoyproxy/ratelimit/src/config"
)

func TestRatelimitToMetadata(t *testing.T) {
	cases := []struct {
		name              string
		req               *pb.RateLimitRequest
		passedDescriptors []int
		failedDescriptors []int
		limitsToCheck     []*config.RateLimit
		statuses          []*pb.RateLimitResponse_DescriptorStatus
		expected          string
	}{
		{
			name: "Single descriptor with single entry, no quota violations",
			req: &pb.RateLimitRequest{
				Domain: "fake-domain",
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{
								Key:   "key1",
								Value: "val1",
							},
						},
					},
				},
			},
			passedDescriptors: nil,
			limitsToCheck:     []*config.RateLimit{nil},
			expected: `{
    "descriptors": [
        {
            "entries": [
                "key1=val1"
            ]
        }
    ],
    "domain": "fake-domain"
}`,
		},
		{
			name: "Single descriptor with quota mode violation",
			req: &pb.RateLimitRequest{
				Domain: "quota-domain",
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{
								Key:   "quota_key",
								Value: "quota_val",
							},
						},
					},
				},
			},
			passedDescriptors: []int{0},
			limitsToCheck: []*config.RateLimit{
				{
					QuotaMode: true,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"name": structpb.NewStringValue("service_1"),
						},
					},
				},
			},
			expected: `{
    "descriptors": [
        {
            "entries": [
                "quota_key=quota_val"
            ]
        }
    ],
    "domain": "quota-domain",
    "metadata": {
        "name": "service_1"
    }
}`,
		},
		{
			name: "Multiple descriptors with mixed quota violations",
			req: &pb.RateLimitRequest{
				Domain: "mixed-domain",
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{
								Key:   "regular_key",
								Value: "regular_val",
							},
						},
					},
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{
								Key:   "quota_key",
								Value: "quota_val",
							},
						},
					},
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{
								Key:   "another_quota",
								Value: "another_val",
							},
						},
					},
				},
			},
			passedDescriptors: []int{1, 2},
			limitsToCheck: []*config.RateLimit{
				{
					QuotaMode: false,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"name": structpb.NewStringValue("service_1"),
						},
					},
				},
				{
					QuotaMode: true,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"name": structpb.NewStringValue("service_2"),
						},
					},
				},
				{
					QuotaMode: true,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"name": structpb.NewStringValue("service_3"),
						},
					},
				},
			},
			expected: `{
    "descriptors": [
        {
            "entries": [
                "regular_key=regular_val"
            ]
        },
        {
            "entries": [
                "quota_key=quota_val"
            ]
        },
        {
            "entries": [
                "another_quota=another_val"
            ]
        }
    ],
    "domain": "mixed-domain",
    "metadata": {
        "name": "service_2"
    }
}`,
		},
		{
			name: "Request with hits addend",
			req: &pb.RateLimitRequest{
				Domain:     "addend-domain",
				HitsAddend: 5,
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{
								Key:   "test_key",
								Value: "test_val",
							},
						},
					},
				},
			},
			passedDescriptors: []int{0},
			limitsToCheck: []*config.RateLimit{
				{
					QuotaMode: true,
				},
			},
			expected: `{
    "descriptors": [
        {
            "entries": [
                "test_key=test_val"
            ]
        }
    ],
    "domain": "addend-domain",
    "hitsAddend": 5
}`,
		},
		{
			name: "Single failed descriptor with full limit info",
			req: &pb.RateLimitRequest{
				Domain: "fail-domain",
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{Key: "route", Value: "api"},
						},
					},
				},
			},
			passedDescriptors: nil,
			failedDescriptors: []int{0},
			limitsToCheck: []*config.RateLimit{
				{
					FullKey: "fail-domain/route/api",
				},
			},
			statuses: []*pb.RateLimitResponse_DescriptorStatus{
				{
					Code: pb.RateLimitResponse_OVER_LIMIT,
					CurrentLimit: &pb.RateLimitResponse_RateLimit{
						RequestsPerUnit: 100,
						Unit:            pb.RateLimitResponse_RateLimit_MINUTE,
					},
				},
			},
			expected: `{
    "descriptors": [
        {
            "entries": [
                "route=api"
            ]
        }
    ],
    "domain": "fail-domain",
    "failed_descriptors": "[{\"entries\":[\"route=api\"], \"limit\":{\"requests_per_unit\":100, \"unit\":\"MINUTE\"}, \"limit_key\":\"fail-domain/route/api\"}]"
}`,
		},
		{
			name: "Mixed passed and failed descriptors",
			req: &pb.RateLimitRequest{
				Domain: "mixed-fail-domain",
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{Key: "route", Value: "ok"},
						},
					},
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{Key: "route", Value: "blocked"},
							{Key: "method", Value: "POST"},
						},
					},
				},
			},
			passedDescriptors: []int{0},
			failedDescriptors: []int{1},
			limitsToCheck: []*config.RateLimit{
				{FullKey: "mixed-fail-domain/route/ok"},
				{FullKey: "mixed-fail-domain/route/blocked"},
			},
			statuses: []*pb.RateLimitResponse_DescriptorStatus{
				{
					Code: pb.RateLimitResponse_OK,
					CurrentLimit: &pb.RateLimitResponse_RateLimit{
						RequestsPerUnit: 1000,
						Unit:            pb.RateLimitResponse_RateLimit_HOUR,
					},
				},
				{
					Code: pb.RateLimitResponse_OVER_LIMIT,
					CurrentLimit: &pb.RateLimitResponse_RateLimit{
						RequestsPerUnit: 10,
						Unit:            pb.RateLimitResponse_RateLimit_SECOND,
					},
				},
			},
			expected: `{
    "descriptors": [
        {"entries": ["route=ok"]},
        {"entries": ["route=blocked", "method=POST"]}
    ],
    "domain": "mixed-fail-domain",
    "failed_descriptors": "[{\"entries\":[\"route=blocked\", \"method=POST\"], \"limit\":{\"requests_per_unit\":10, \"unit\":\"SECOND\"}, \"limit_key\":\"mixed-fail-domain/route/blocked\"}]"
}`,
		},
		{
			name: "Failed descriptor with nil CurrentLimit omits limit field",
			req: &pb.RateLimitRequest{
				Domain: "no-limit-domain",
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{Key: "key", Value: "val"},
						},
					},
				},
			},
			passedDescriptors: nil,
			failedDescriptors: []int{0},
			limitsToCheck: []*config.RateLimit{
				{FullKey: "no-limit-domain/key/val"},
			},
			statuses: []*pb.RateLimitResponse_DescriptorStatus{
				{
					Code:         pb.RateLimitResponse_OVER_LIMIT,
					CurrentLimit: nil,
				},
			},
			expected: `{
    "descriptors": [
        {"entries": ["key=val"]}
    ],
    "domain": "no-limit-domain",
    "failed_descriptors": "[{\"entries\":[\"key=val\"], \"limit_key\":\"no-limit-domain/key/val\"}]"
}`,
		},
		{
			name: "No failed descriptors produces no failed_descriptors field",
			req: &pb.RateLimitRequest{
				Domain: "all-ok-domain",
				Descriptors: []*ratelimitv3.RateLimitDescriptor{
					{
						Entries: []*ratelimitv3.RateLimitDescriptor_Entry{
							{Key: "key", Value: "val"},
						},
					},
				},
			},
			passedDescriptors: []int{0},
			failedDescriptors: nil,
			limitsToCheck:     []*config.RateLimit{{FullKey: "all-ok-domain/key/val"}},
			statuses: []*pb.RateLimitResponse_DescriptorStatus{
				{Code: pb.RateLimitResponse_OK},
			},
			expected: `{
    "descriptors": [
        {"entries": ["key=val"]}
    ],
    "domain": "all-ok-domain"
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ratelimitToMetadata(tc.req, tc.passedDescriptors, tc.failedDescriptors, tc.limitsToCheck, tc.statuses)
			expected := &structpb.Struct{}
			err := protojson.Unmarshal([]byte(tc.expected), expected)
			require.NoError(t, err)

			if diff := cmp.Diff(got, expected, protocmp.Transform()); diff != "" {
				t.Errorf("diff: %s", diff)
			}
		})
	}
}

// Package sg contains types for the SendGrid integration.
package sg

import "strings"

var _ error = Error{}

// https://sendgrid.com/docs/api-reference/
type (
	Enable struct {
		Enable bool `json:"enable"`
	}

	Message struct {
		Subject          string            `json:"subject"`
		Personalizations []Personalization `json:"personalizations"`
		Content          []Content         `json:"content"`
		Attachments      []Attachment      `json:"attachments,omitempty"`
		From             Address           `json:"from"`
		ReplyTo          *Address          `json:"reply_to,omitempty"` // TODO: never set
		Headers          map[string]string `json:"headers,omitempty"`

		SandboxMode *Enable `json:"sandbox_mode,omitempty"`

		// Never set by default.

		TemplateID   string   `json:"template_id,omitempty"`
		categories   []string `json:"categories,omitempty"`
		CustomArgs   string   `json:"custom_args,omitempty"`
		SendAt       int64    `json:"send_at,omitempty"`
		BatchID      string   `json:"batch_id,omitempty"`
		MailSettings []struct {
			BypassListManagement        *Enable `json:"bypass_list_management,omitempty"`
			BypassSpamManagement        *Enable `json:"bypass_spam_management,omitempty"`
			BypassBounceManagement      *Enable `json:"bypass_bounce_management,omitempty"`
			BypassUnsubscribeManagement *Enable `json:"bypass_unsubscribe_management"`
		} `json:"mail_settings,omitempty"`
		Footer           *Footer           `json:"footer,omitempty"`
		SpamCheck        *SpamCheck        `json:"spam_check,omitempty"`
		TrackingSettings *TrackingSettings `json:"tracking_settings,omitempty"`
	}

	Personalization struct {
		To  []Address `json:"to,omitempty"`
		Cc  []Address `json:"cc,omitempty"`
		Bcc []Address `json:"bcc,omitempty"`
	}

	Content struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}

	Attachment struct {
		Type        string `json:"type"`
		Content     string `json:"content"` // base64
		Filename    string `json:"filename,omitempty"`
		Disposition string `json:"disposition,omitempty"`
		ContentID   string `json:"content_id,omitempty"`
	}

	Address struct {
		Name  string `json:"name,omitempty"`
		Email string `json:"email"`
	}

	Footer struct {
		Enable bool   `json:"enable"`
		Text   string `json:"text,omitempty"`
		HTML   string `json:"html,omitempty"`
	}

	SpamCheck struct {
		Enable    bool   `json:"enable"`
		Treshold  int    `json:"treshold"`
		PostToURL string `json:"post_to_url,omitempty"`
	}

	TrackingSettings struct {
		ClickTracking        *ClickTracking        `json:"click_tracking,omitempty"`
		OpenTracking         *OpenTracking         `json:"open_tracking,omitempty"`
		SubscriptionTracking *SubscriptionTracking `json:"subscription_tracking,omitempty"`
		GAnalytics           *GAnalytics           `json:"ganalytics,omitempty"`
	}

	ClickTracking struct {
		Enable     bool `json:"enable"`
		EnableText bool `json:"enable_text,omitempty"`
	}
	OpenTracking struct {
		Enable          bool   `json:"enable"`
		SubstitutionTag string `json:"substitution_tag,omitempty"`
	}
	SubscriptionTracking struct {
		Enable          bool   `json:"enable"`
		Text            string `json:"text,omitempty"`
		HTML            string `json:"html,omitempty"`
		SubstitutionTag string `json:"substitution_tag,omitempty"`
	}
	GAnalytics struct {
		Enable       bool   `json:"enable"`
		UTMSource    string `json:"utm_source,omitempty"`
		UTMMedium    string `json:"utm_medium,omitempty"`
		UTMTerm      string `json:"utm_term,omitempty"`
		UTMContent   string `json:"utm_content,omitempty"`
		UTMCampaigns string `json:"utm_campaigns,omitempty"`
	}

	Error struct {
		Status     string `json:"-"`
		StatusCode int    `json:"-"`

		Errors []struct {
			Message string `json:"message"`
			Field   string `json:"field"`
			Help    string `json:"help"`
		} `json:"errors"`
	}
)

func (s Error) Error() string {
	b := new(strings.Builder)
	b.WriteString(s.Status)
	b.WriteString(": ")

	for i, m := range s.Errors {
		if m.Field != "" {
			b.WriteString(m.Field)
			b.WriteString(": ")
		}
		b.WriteString(m.Message)
		if i != len(s.Errors)-1 {
			b.WriteString(", ")
		}
	}

	return b.String()
}

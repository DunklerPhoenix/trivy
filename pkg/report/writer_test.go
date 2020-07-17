package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportWriter_Table(t *testing.T) {
	testCases := []struct {
		name           string
		detectedVulns  []types.DetectedVulnerability
		expectedOutput string
		light          bool
	}{
		{
			name: "happy path full",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foobar",
						Description: "baz",
						Severity:    "HIGH",
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION | TITLE  |
+---------+------------------+----------+-------------------+---------------+--------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         | foobar |
+---------+------------------+----------+-------------------+---------------+--------+
`,
		},
		{
			name:  "happy path light",
			light: true,
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foobar",
						Description: "baz",
						Severity:    "HIGH",
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |
+---------+------------------+----------+-------------------+---------------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         |
+---------+------------------+----------+-------------------+---------------+
`,
		},
		{
			name: "no title for vuln",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Description: "foobar",
						Severity:    "HIGH",
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION | TITLE  |
+---------+------------------+----------+-------------------+---------------+--------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         | foobar |
+---------+------------------+----------+-------------------+---------------+--------+
`,
		},
		{
			name: "long title for vuln",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "a b c d e f g h i j k l m n o p q r s t u v",
						Severity: "HIGH",
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+----------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |           TITLE            |
+---------+------------------+----------+-------------------+---------------+----------------------------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         | a b c d e f g h i j k l... |
+---------+------------------+----------+-------------------+---------------+----------------------------+
`,
		},
		{
			name:           "no vulns",
			detectedVulns:  []types.DetectedVulnerability{},
			expectedOutput: ``,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputResults := report.Results{
				{
					Target:          "foo",
					Vulnerabilities: tc.detectedVulns,
				},
			}
			tableWritten := bytes.Buffer{}
			assert.NoError(t, report.WriteResults("table", &tableWritten, nil, inputResults, "", tc.light), tc.name)
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}

func TestReportWriter_JSON(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		expectedJSON  report.Results
	}{
		{
			name: "happy path",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foobar",
						Description: "baz",
						Severity:    "HIGH",
					},
				},
			},
			expectedJSON: report.Results{
				report.Result{
					Target: "foojson",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "123",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "HIGH",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			jw := report.JsonWriter{}
			jsonWritten := bytes.Buffer{}
			jw.Output = &jsonWritten

			inputResults := report.Results{
				{
					Target:          "foojson",
					Vulnerabilities: tc.detectedVulns,
				},
			}

			assert.NoError(t, report.WriteResults("json", &jsonWritten, nil, inputResults, "", false), tc.name)

			writtenResults := report.Results{}
			errJson := json.Unmarshal([]byte(jsonWritten.String()), &writtenResults)
			assert.NoError(t, errJson, "invalid json written", tc.name)

			assert.Equal(t, tc.expectedJSON, writtenResults, tc.name)
		})
	}

}

func TestReportWriter_Template(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		template      string
		expected      string
	}{
		{
			name: "happy path",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "foo",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String()},
				},
				{
					VulnerabilityID: "CVE-2019-0001",
					PkgName:         "baz",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
			},
			template: "{{ range . }}{{ range .Vulnerabilities}}{{ println .VulnerabilityID .Severity }}{{ end }}{{ end }}",
			expected: "CVE-2019-0000 HIGH\nCVE-2019-0000 HIGH\nCVE-2019-0001 CRITICAL\n",
		},
		{
			name: "happy path",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:       `gcc: POWER9 "DARN" RNG intrinsic produces repeated output`,
						Description: `curl version curl 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl < 7.20.0 and curl >= 7.60.0.`,
						Severity:    "HIGH",
					},
				},
			},

			template: `<testsuites>
{{- range . -}}
{{- $failures := len .Vulnerabilities }}
    <testsuite tests="1" failures="{{ $failures }}" time="" name="{{  .Target }}">
	{{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Vulnerabilities }}
        <testcase classname="{{ .PkgName }}-{{ .InstalledVersion }}" name="[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}" time="">
            <failure message={{escapeXML .Title | printf "%q" }} type="description">{{escapeXML .Description | printf "%q" }}</failure>
        </testcase>
    {{- end }}
	</testsuite>
{{- end }}
</testsuites>`,

			expected: `<testsuites>
    <testsuite tests="1" failures="1" time="" name="foojunit">
        <properties>
            <property name="type" value="test"></property>
        </properties>
        <testcase classname="foo-1.2.3" name="[HIGH] 123" time="">
            <failure message="gcc: POWER9 &#34;DARN&#34; RNG intrinsic produces repeated output" type="description">"curl version curl 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl &lt; 7.20.0 and curl &gt;= 7.60.0."</failure>
        </testcase>
	</testsuite>
</testsuites>`,
		},
		{
			name: "happy path with/without period description should return with period",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "foo",
					Vulnerability: dbTypes.Vulnerability{
						Description: "without period",
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Description: "with period.",
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Description: `with period and unescaped string curl: Use-after-free when closing 'easy' handle in Curl_close().`,
					},
				},
			},
			template: `{{ range . }}{{ range .Vulnerabilities}}{{.VulnerabilityID}} {{ endWithPeriod (escapeString .Description) | printf "%q" }}{{ end }}{{ end }}`,
			expected: `CVE-2019-0000 "without period."CVE-2019-0000 "with period."CVE-2019-0000 "with period and unescaped string curl: Use-after-free when closing &#39;easy&#39; handle in Curl_close()."`,
		},
		{
			name:          "happy path: env var parsing and getCurrentTime",
			detectedVulns: []types.DetectedVulnerability{},
			template:      `{{ toLower (getEnv "AWS_ACCOUNT_ID") }} {{ getCurrentTime }}`,
			expected:      `123456789012 2020-08-10T07:28:17.000958601Z`,
		},
		{
			name: "html",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.3.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:      "foobar",
						Severity:   "LOW",
						References: []string{"https://www.google.com"},
					},
				},
				{
					VulnerabilityID:  "456",
					PkgName:          "bar",
					InstalledVersion: "2.2.3",
					FixedVersion:     "3.5.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:      "barbar",
						Severity:   "HIGH",
						References: []string{"https://www.google.at"},
					},
				},
				{
					VulnerabilityID:  "789",
					PkgName:          "bar",
					InstalledVersion: "3.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:      "foofoo",
						Severity:   "HIGH",
						References: []string{"https://www.google.biz"},
					},
				},
			},
			template: `<!DOCTYPE html>
<html>
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
{{- if . }}
	<style>
		* {
		font-family: Arial, Helvetica, sans-serif;
		}
		h1 {
		text-align: center;
		}
		.group-header th {
		font-size: 200%;
		}
		.sub-header th {
		font-size: 150%;
		}
		table, th, td {
		border: 1px solid black;
		border-collapse: collapse;
		white-space: nowrap;
		padding: .3em;
		}
		table {
		margin: 0 auto;
		}
		.severity {
		text-align: center;
		font-weight: bold;
		color: #fafafa;
		}
		.severity-LOW .severity { background-color: #5fbb31; }
		.severity-MEDIUM .severity { background-color: #e9c600; }
		.severity-HIGH .severity { background-color: #ff8800; }
		.severity-CRITICAL .severity { background-color: #e40000; }
		.severity-UNKNOWN .severity { background-color: #747474; }
		.severity-LOW { background-color: #5fbb3160; }
		.severity-MEDIUM { background-color: #e9c60060; }
		.severity-HIGH { background-color: #ff880060; }
		.severity-CRITICAL { background-color: #e4000060; }
		.severity-UNKNOWN { background-color: #74747460; }
		table tr td:first-of-type {
		font-weight: bold;
		}
		.links a,
		.links[data-more-links=on] a {
		display: block;
		}
		.links[data-more-links=off] a:nth-of-type(1n+5) {
		display: none;
		}
		a.toggle-more-links { cursor: pointer; }
	</style>
	<title>{{- escapeXML ( index . 0 ).Target }} - Trivy Report - {{ getCurrentTime }}</title>
	<script>
		window.onload = function() {
		document.querySelectorAll('td.links').forEach(function(linkCell) {
			var links = [].concat.apply([], linkCell.querySelectorAll('a'));
			[].sort.apply(links, function(a, b) {
			return a.href > b.href ? 1 : -1;
			});
			links.forEach(function(link, idx) {
			if (links.length > 3 && 3 === idx) {
				var toggleLink = document.createElement('a');
				toggleLink.innerText = "Toggle more links";
				toggleLink.href = "#toggleMore";
				toggleLink.setAttribute("class", "toggle-more-links");
				linkCell.appendChild(toggleLink);
			}
			linkCell.appendChild(link);
			});
		});
		document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
			toggleLink.onclick = function() {
			var expanded = toggleLink.parentElement.getAttribute("data-more-links");
			toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
			return false;
			};
		});
		};
	</script>
	</head>
	<body>
	<h1>{{- escapeXML ( index . 0 ).Target }} - Trivy Report - {{ getCurrentTime }}</h1>
	<table>
	{{- range . }}
		<tr class="group-header"><th colspan="6">{{ escapeXML .Type }}</th></tr>
		{{- if (eq (len .Vulnerabilities) 0) }}
		<tr><th colspan="6">No Vulnerabilities found</th></tr>
		{{- else }}
		<tr class="sub-header">
		<th>Package</th>
		<th>Installed Version</th>
		<th>Level</th>
		<th>Vulnerability ID</th>
		<th>Fixed Version</th>
		<th>Links</th>
		</tr>
		{{- range .Vulnerabilities }}
		<tr class="severity-{{ escapeXML .Vulnerability.Severity }}">
		<td class="pkg-name">{{ escapeXML .PkgName }}</td>
		<td class="pkg-version">{{ escapeXML .InstalledVersion }}</td>
		<td class="severity">{{ escapeXML .Vulnerability.Severity }}</td>
		<td>{{ escapeXML .VulnerabilityID }}</td>
		<td>{{ escapeXML .FixedVersion }}</td>
		<td class="links" data-more-links="off">
			{{- range .Vulnerability.References }}
			<a href={{ escapeXML . | printf "%q" }}>{{ escapeXML . }}</a>
			{{- end }}
		</td>
		</tr>
		{{- end }}
		{{- end }}
	{{- end }}
	</table>
{{- else }}
	</head>
	<body>
	<h1>Trivy Returned Empty Report</h1>
{{- end }}
	</body>
</html>`,
			expected: `<!DOCTYPE html>
<html>
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<style>
		* {
		font-family: Arial, Helvetica, sans-serif;
		}
		h1 {
		text-align: center;
		}
		.group-header th {
		font-size: 200%;
		}
		.sub-header th {
		font-size: 150%;
		}
		table, th, td {
		border: 1px solid black;
		border-collapse: collapse;
		white-space: nowrap;
		padding: .3em;
		}
		table {
		margin: 0 auto;
		}
		.severity {
		text-align: center;
		font-weight: bold;
		color: #fafafa;
		}
		.severity-LOW .severity { background-color: #5fbb31; }
		.severity-MEDIUM .severity { background-color: #e9c600; }
		.severity-HIGH .severity { background-color: #ff8800; }
		.severity-CRITICAL .severity { background-color: #e40000; }
		.severity-UNKNOWN .severity { background-color: #747474; }
		.severity-LOW { background-color: #5fbb3160; }
		.severity-MEDIUM { background-color: #e9c60060; }
		.severity-HIGH { background-color: #ff880060; }
		.severity-CRITICAL { background-color: #e4000060; }
		.severity-UNKNOWN { background-color: #74747460; }
		table tr td:first-of-type {
		font-weight: bold;
		}
		.links a,
		.links[data-more-links=on] a {
		display: block;
		}
		.links[data-more-links=off] a:nth-of-type(1n+5) {
		display: none;
		}
		a.toggle-more-links { cursor: pointer; }
	</style>
	<title>foojunit - Trivy Report - 2020-08-10T07:28:17.000958601Z</title>
	<script>
		window.onload = function() {
		document.querySelectorAll('td.links').forEach(function(linkCell) {
			var links = [].concat.apply([], linkCell.querySelectorAll('a'));
			[].sort.apply(links, function(a, b) {
			return a.href > b.href ? 1 : -1;
			});
			links.forEach(function(link, idx) {
			if (links.length > 3 && 3 === idx) {
				var toggleLink = document.createElement('a');
				toggleLink.innerText = "Toggle more links";
				toggleLink.href = "#toggleMore";
				toggleLink.setAttribute("class", "toggle-more-links");
				linkCell.appendChild(toggleLink);
			}
			linkCell.appendChild(link);
			});
		});
		document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
			toggleLink.onclick = function() {
			var expanded = toggleLink.parentElement.getAttribute("data-more-links");
			toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
			return false;
			};
		});
		};
	</script>
	</head>
	<body>
	<h1>foojunit - Trivy Report - 2020-08-10T07:28:17.000958601Z</h1>
	<table>
		<tr class="group-header"><th colspan="6">test</th></tr>
		<tr class="sub-header">
		<th>Package</th>
		<th>Installed Version</th>
		<th>Level</th>
		<th>Vulnerability ID</th>
		<th>Fixed Version</th>
		<th>Links</th>
		</tr>
		<tr class="severity-LOW">
		<td class="pkg-name">foo</td>
		<td class="pkg-version">1.2.3</td>
		<td class="severity">LOW</td>
		<td>123</td>
		<td>3.3.5</td>
		<td class="links" data-more-links="off">
			<a href="https://www.google.com">https://www.google.com</a>
		</td>
		</tr>
		<tr class="severity-HIGH">
		<td class="pkg-name">bar</td>
		<td class="pkg-version">2.2.3</td>
		<td class="severity">HIGH</td>
		<td>456</td>
		<td>3.5.5</td>
		<td class="links" data-more-links="off">
			<a href="https://www.google.at">https://www.google.at</a>
		</td>
		</tr>
		<tr class="severity-HIGH">
		<td class="pkg-name">bar</td>
		<td class="pkg-version">3.2.3</td>
		<td class="severity">HIGH</td>
		<td>789</td>
		<td>3.4.5</td>
		<td class="links" data-more-links="off">
			<a href="https://www.google.biz">https://www.google.biz</a>
		</td>
		</tr>
	</table>
	</body>
</html>`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report.Now = func() time.Time {
				return time.Date(2020, 8, 10, 7, 28, 17, 958601, time.UTC)
			}
			os.Setenv("AWS_ACCOUNT_ID", "123456789012")
			tmplWritten := bytes.Buffer{}
			inputResults := report.Results{
				{
					Target:          "foojunit",
					Type:            "test",
					Vulnerabilities: tc.detectedVulns,
				},
			}

			assert.NoError(t, report.WriteResults("template", &tmplWritten, nil, inputResults, tc.template, false))
			assert.Equal(t, tc.expected, tmplWritten.String())
		})
	}
}

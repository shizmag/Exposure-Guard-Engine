// Synthetic client-side JavaScript bundle for secret-leak regression testing
const config = {
  awsKey: "AKIAIOSFODNN7EXAMPLE",
  githubToken: "ghp_FakeGitHubPersonalAccessToken123456",
  jwtAuth: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  dbEndpoint: "postgres://dbuser:superSecretPassword987!@db.internal.example.com:5432",
  slackWebhook: "xoxb-123456789012-1234567890123-FakeSlackTokenABCDEFGHIJKL",
  apiUrl: "https://admin:SuperSecretUserPass@example.com/api?token=secretQueryToken12345"
};
export default config;

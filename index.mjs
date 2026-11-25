import {
  basic,
  bearer,
  check,
  connection,
  credential,
  error,
  matchesState,
  oauth1Authorization,
  query,
  safeEndpoint,
  secretPath,
  segment,
  service,
  setting,
  stateOption,
  target,
  text,
  verdict,
  z,
} from '@cairul/plugin-kit';
import { connectAuthorization } from './connect-auth.mjs';

export default function jira({ apiVersion, siteUrl, consumerKey, privateKeyFile, connectAppKey, ...options } = {}) {
  const prefix = 'JIRA';
  const version = String(setting(prefix, 'API_VERSION', apiVersion ?? '3'));
  if (!['2', '3'].includes(version)) throw new Error('Set Jira apiVersion to 2 or 3.');
  const resource = 'rest/api/' + version;
  const web = setting(prefix, 'SITE_URL', siteUrl);
  const consumer = setting(prefix, 'CONSUMER_KEY', consumerKey);
  const appKey = setting(prefix, 'CONNECT_APP_KEY', connectAppKey);
  if (privateKeyFile !== undefined) secretPath.parse(privateKeyFile);
  const getKey = credential(prefix, 'OAUTH_PRIVATE_KEY', { file: privateKeyFile, required: true });
  const api = connection(options, {
    prefix,
    tokenEnv: 'JIRA_API_TOKEN',
    required: true,
    defaultAuth: (email) => (email ? 'basic' : 'bearer'),
    authModes: {
      basic,
      bearer,
      'connect-jwt': (token) => ({ authorization: 'JWT ' + token }),
      connect: (secret, _email, _signal, request) => {
        if (!appKey) throw new Error('Set the Jira Connect app key.');
        return connectAuthorization({ ...request, appKey, secret });
      },
      oauth1: async (token, _email, signal, request) => {
        if (!consumer) throw new Error('Set the Jira OAuth consumer key.');
        const privatePem = await getKey(signal);
        return { authorization: oauth1Authorization({ ...request, key: consumer, token, privatePem }) };
      },
    },
  });
  const host = web ? safeEndpoint(web).host : api.host;
  function issueCheck(fields, schema, evaluate) {
    return check(z.strictObject({ issue: text.optional(), ...schema }), (config, context) =>
      service(async () => {
        const id = target(config.issue, context.workItemUrl, [host], /\/browse\/([^/]+)(?:\/|$)/);
        const response = await api.request(`${resource}/issue/${segment(id)}`, {
          signal: context.signal,
          query: { fields: typeof fields === 'function' ? fields(config) : fields },
        });
        if (!response.fields) return error('Jira returned no issue fields.');
        return evaluate(response.fields, config);
      })
    );
  }
  return {
    checkKinds: {
      'jira.issue-status': issueCheck('status', { state: stateOption }, (issue, { state }) =>
        matchesState(issue.status?.name, state, 'Issue')
      ),
      'jira.issue-resolution': issueCheck('resolution', { state: stateOption }, (issue, { state }) =>
        matchesState(issue.resolution?.name ?? 'unresolved', state, 'Issue resolution')
      ),
      'jira.issue-field-present': issueCheck(
        ({ field }) => field,
        { field: text.regex(/^[a-zA-Z][a-zA-Z0-9_]*$/) },
        (issue, { field }) => {
          const value = issue[field];
          return verdict(
            value !== undefined && value !== null && value !== '' && (!Array.isArray(value) || value.length > 0),
            `Required Jira field: ${field}.`
          );
        }
      ),
      'jira.no-blockers': issueCheck(
        'issuelinks',
        { relationship: text.default('is blocked by') },
        (issue, { relationship }) => {
          if (!Array.isArray(issue.issuelinks)) return error('Jira returned no issue links.');
          const blockers = issue.issuelinks.filter(
            ({ type, inwardIssue }) => type?.inward === relationship && inwardIssue
          );
          const categories = blockers.map(({ inwardIssue }) => inwardIssue.fields?.status?.statusCategory?.key);
          if (categories.some((category) => !category)) return error('Jira returned incomplete blocker status.');
          const open = categories.filter((category) => category !== 'done').length;
          return verdict(open === 0, `${open} linked blockers remain open.`);
        }
      ),
      'jira.jql-matches': check(
        z.strictObject({ jql: text, expected: z.enum(['some', 'none']).default('some') }),
        ({ jql, expected }, { signal }) =>
          service(async () => {
            const path = version === '3' ? resource + '/search/jql' : resource + '/search';
            const response =
              api.authMode === 'connect' || api.authMode === 'connect-jwt'
                ? await api.request(path, { signal, query: { jql, maxResults: 1, fields: 'key' } })
                : await query(api, path, { jql, maxResults: 1, fields: ['key'] }, signal);
            if (!Array.isArray(response.issues)) return error('Jira returned no search results.');
            const hasResults = response.issues.length > 0;
            if (!hasResults && response.nextPageToken) return error('Jira returned an incomplete search result.');
            return verdict(
              hasResults === (expected === 'some'),
              hasResults ? 'JQL matched an issue.' : 'JQL returned no issues.'
            );
          })
      ),
    },
  };
}

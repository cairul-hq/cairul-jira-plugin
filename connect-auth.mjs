import { Buffer } from 'node:buffer';
import { createHash, createHmac } from 'node:crypto';

import { oauthEncode as encode } from '@cairul/pdk';

const json64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

export function connectAuthorization({ appKey, secret, url, path, method }) {
  const parameters = new Map();
  for (const [name, value] of url.searchParams) {
    if (name === 'jwt') continue;
    const encodedName = encode(name);
    const values = parameters.get(encodedName) ?? [];
    values.push(encode(value));
    parameters.set(encodedName, values);
  }
  const query = [...parameters.keys()]
    .sort()
    .map((name) => name + '=' + parameters.get(name).sort().join('%2C'))
    .join('&');
  const uri = ('/' + path.replace(/^\/+|\/+$/g, '')).replaceAll('&', '%26');
  const qsh = createHash('sha256')
    .update(method.toUpperCase() + '&' + uri + '&' + query)
    .digest('hex');
  const iat = Math.floor(Date.now() / 1000);
  const unsigned = json64({ alg: 'HS256', typ: 'JWT' }) + '.' + json64({ iss: appKey, iat, exp: iat + 180, qsh });
  const signature = createHmac('sha256', secret).update(unsigned).digest('base64url');
  return { authorization: 'JWT ' + unsigned + '.' + signature };
}

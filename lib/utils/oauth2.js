import {
  curry,
} from 'ramda';

export const authorizationUrl = curry(
  (url, appId, callback, scope, state='default', responseType = 'token') =>
    `${url}?scope=${encodeURIComponent(scope)}&
      redirect_uri=${encodeURIComponent(callback)}&
      state=${encodeURIComponent(state)}&
      response_type=${responseType}&
      client_id=${appId}`.replace(/\s+/g, ''),
  );

export const getHeaders = token => ({ Authorization: `Bearer ${token}` });

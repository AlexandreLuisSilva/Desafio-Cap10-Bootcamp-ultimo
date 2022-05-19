import jwtDecode from 'jwt-decode';
import { getAuthData, removeAuthData } from './storage';
import { requestBackend } from './requests';
import { AxiosRequestConfig } from 'axios';

export type Role = 'ROLE_VISITOR' | 'ROLE_MEMBER';

export type TokenData = {
  exp: number;
  user_name: string;
  authorities: Role[];
};

export const getTokenData = (): TokenData | undefined => {
  try {
    return jwtDecode(getAuthData().access_token) as TokenData;
  } catch (error) {
    return undefined;
  }
};

// Incluido cheque de email, pois com as mudancas de projeto, 
// o token do DSCatalog estava sendo considerado pelo MovieFlix

export const isAuthenticated = (): boolean => {
  // checa se o usuario esta no sistema (devido mistura)
  const tokenData = getTokenData();

  // se existe
  if (tokenData) {
    const params: AxiosRequestConfig = {
      method: 'GET',
      url: `/users/${tokenData.user_name}`,
      withCredentials: true,
    };

    requestBackend(params).then((response) => {
      if (response.data === false) {
        removeAuthData();
        return false;
      }
    });

    return tokenData.exp * 1000 > Date.now() ? true : false;
  }
  return false;
};

export const hasAnyRoles = (roles: Role[]): boolean => {
  if (roles.length === 0) {
    return true;
  }
  const tokenData = getTokenData();

  if (tokenData !== undefined) {
    return roles.some((role) => tokenData.authorities.includes(role));
  }

  /* idem alta ordem acima
    if (tokenData !== undefined) {
      for (var i = 0; i < roles.length; i++) {
        if (tokenData.authorities.includes(roles[i])) {
          return true;
        }
      }
    }
    */

  return false;
};

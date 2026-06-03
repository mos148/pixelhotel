
export default {
  bootstrap: () => import('./main.server.mjs').then(m => m.default),
  inlineCriticalCss: true,
  baseHref: '/',
  locale: undefined,
  routes: [
  {
    "renderMode": 2,
    "redirectTo": "/login",
    "route": "/"
  },
  {
    "renderMode": 2,
    "route": "/login"
  },
  {
    "renderMode": 2,
    "route": "/register"
  },
  {
    "renderMode": 2,
    "route": "/home"
  },
  {
    "renderMode": 2,
    "route": "/hotel"
  }
],
  entryPointToBrowserMapping: undefined,
  assets: {
    'index.csr.html': {size: 1527, hash: 'b5c6b7afded6b9965bb9cb20d62eaa2f4219543d702dc1f358a069b04bd41e02', text: () => import('./assets-chunks/index_csr_html.mjs').then(m => m.default)},
    'index.server.html': {size: 1521, hash: 'e5ff73cd4ca4fd109bac4ccdfdfe57c88010b32b90a883e29747f0de1ae0b5d5', text: () => import('./assets-chunks/index_server_html.mjs').then(m => m.default)},
    'login/index.html': {size: 17298, hash: '75b440914e3a9ccb69c22c64053d2a643c89868eac80c9dea4650bdb087d0a00', text: () => import('./assets-chunks/login_index_html.mjs').then(m => m.default)},
    'home/index.html': {size: 240, hash: 'db096474d521163c4f5fb7d700305222bcea1012b38583442ad232da75e59192', text: () => import('./assets-chunks/home_index_html.mjs').then(m => m.default)},
    'hotel/index.html': {size: 240, hash: 'db096474d521163c4f5fb7d700305222bcea1012b38583442ad232da75e59192', text: () => import('./assets-chunks/hotel_index_html.mjs').then(m => m.default)},
    'register/index.html': {size: 8783, hash: 'e564c5e27eb0e8076f04e40f81da076d2ef4a5a40e411bfb5a3fea30bdc8adb0', text: () => import('./assets-chunks/register_index_html.mjs').then(m => m.default)},
    'styles-BFFTOAXF.css': {size: 7190, hash: 'D94JvEhI+ks', text: () => import('./assets-chunks/styles-BFFTOAXF_css.mjs').then(m => m.default)}
  },
};

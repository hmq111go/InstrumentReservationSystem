// 前端配置文件
window.APP_CONFIG = {
  // 生产环境 API 地址（通过 Nginx 代理）
  PRODUCTION_API: 'http://1.13.176.116',
  
  // 开发环境 API 地址
  DEVELOPMENT_API: 'http://127.0.0.1:5011',
  
  // 获取当前环境的 API 地址
  getApiUrl: function() {
    // 如果当前页面是通过 http/https 访问的，使用当前域名
    if (location.origin && location.protocol !== 'file:') {
      return location.origin;
    }
    
    // 从 localStorage 获取用户设置的 API 地址
    const storedApi = localStorage.getItem('API');
    if (storedApi) {
      return storedApi;
    }
    
    // 根据域名判断环境
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
      return this.DEVELOPMENT_API;
    } else {
      return this.PRODUCTION_API;
    }
  }
};

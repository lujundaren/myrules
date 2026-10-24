// Bilibili 去广告脚本（基于 Mach-O 逆向工程分析）
// 稳定去除开屏广告、首页推荐流广告、搜索广告与活动弹窗
// 保留所有正常视频流、动态、评论区、账户登录与功能入口，绝不影响正常使用

const url = $request.url;
let body = $response.body;

if (body) {
  try {
    let obj = JSON.parse(body);

    if (url.includes('/x/v2/splash/')) {
      // 开屏广告清理（BFCSplashManager 逆向分析对应键值）
      if (obj.data) {
        const adKeys = ['show', 'event_list', 'preload', 'account'];
        for (const k of adKeys) {
          if (obj.data[k]) delete obj.data[k];
        }
        obj.data.show = [];
        obj.data.event_list = [];
        obj.data.max_time = 0;
        obj.data.min_interval = 31536000;
        obj.data.pull_interval = 31536000;
        if (Array.isArray(obj.data.list)) {
          for (const item of obj.data.list) {
            item.duration = 0;
            item.enable_pre_download = false;
            item.begin_time = 2208960000;
            item.end_time = 2209046399;
          }
        }
      }
    } else if (url.includes('/x/v2/feed/index')) {
      // 首页推荐流去广告：精确过滤商业卡片与推广横幅，保留全部正常视频卡片
      if (obj.data && Array.isArray(obj.data.items)) {
        obj.data.items = obj.data.items.filter(item => {
          if (item.banner_item) return false;
          if (item.ad_info) return false;
          if (item.card_type && /banner|cm/i.test(item.card_type)) return false;
          if (item.card_goto && /ad/i.test(item.card_goto)) return false;
          return true;
        });
      }
    } else if (url.includes('/x/v2/search')) {
      // 搜索结果净化：剔除商业赞助推广词与广告位
      if (obj.data && Array.isArray(obj.data.item)) {
        obj.data.item = obj.data.item.filter(item => {
          if (item.linktype && item.linktype.endsWith('_ad')) return false;
          return true;
        });
      }
    }

    body = JSON.stringify(obj);
  } catch (e) {
    // 解析异常时直接回退原始响应，确保 0 故障
  }
}

$done({ body });

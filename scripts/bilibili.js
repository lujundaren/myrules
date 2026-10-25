// Bilibili 全功能净化脚本（Shadowrocket / Surge 通用版）
// 完整保留原版页面元素与底栏设定（底栏三键、个人中心精简、官方频道模块精简）
// 补全：播放器暂停广告、详情页顶部横幅广告、搜索页面推广广告视频

const url = $request.url;
let body = $response.body;

if (body) {
  try {
    let obj = JSON.parse(body);

    // 1. 顶栏与底栏 Tab 页面布局定制（保留直播、推荐、热门、动画、影视；底栏保留：首页、动态、我的）
    if (url.includes('/x/resource/show/tab/v2')) {
      if (obj.data) {
        obj.data.tab = [
          { pos: 1, id: 731, name: "直播", tab_id: "直播tab", uri: "bilibili://live/home" },
          { pos: 2, id: 477, name: "推荐", tab_id: "推荐tab", uri: "bilibili://pegasus/promo", default_selected: 1 },
          { pos: 3, id: 478, name: "热门", tab_id: "热门tab", uri: "bilibili://pegasus/hottopic" },
          { pos: 4, id: 3502, name: "动画", tab_id: "bangumi", uri: "bilibili://pgc/bangumi_v2" },
          { pos: 5, id: 3503, name: "影视", tab_id: "film", uri: "bilibili://pgc/cinema_v2" }
        ];
        obj.data.top = [
          { pos: 1, id: 176, name: "消息", tab_id: "消息Top", uri: "bilibili://link/im_home", icon: "http://i0.hdslb.com/bfs/archive/d43047538e72c9ed8fd8e4e34415fbe3a4f632cb.png" }
        ];
        obj.data.bottom = [
          { pos: 1, id: 177, name: "首页", tab_id: "home", uri: "bilibili://main/home/", icon: "http://i0.hdslb.com/bfs/archive/63d7ee88d471786c1af45af86e8cb7f607edf91b.png", icon_selected: "http://i0.hdslb.com/bfs/archive/e5106aa688dc729e7f0eafcbb80317feb54a43bd.png" },
          { pos: 2, id: 179, name: "动态", tab_id: "dynamic", uri: "bilibili://following/home/", icon: "http://i0.hdslb.com/bfs/archive/86dfbe5fa32f11a8588b9ae0fccb77d3c27cedf6.png", icon_selected: "http://i0.hdslb.com/bfs/archive/25b658e1f6b6da57eecba328556101dbdcb4b53f.png" },
          { pos: 5, id: 181, name: "我的", tab_id: "我的Bottom", uri: "bilibili://user_center/", icon: "http://i0.hdslb.com/bfs/archive/4b0b2c49ffeb4f0c2e6a4cceebeef0aab1c53fe1.png", icon_selected: "http://i0.hdslb.com/bfs/archive/a54a8009116cb896e64ef14dcf50e5cade401e00.png" }
        ];
      }
    }

    // 2. 个人中心净化（精简离线缓存、历史记录、我的收藏、稍后再看、联系客服、设置）
    else if (url.includes('/x/v2/account/mine')) {
      if (obj.data) {
        delete obj.data.answer;
        delete obj.data.live_tip;
        delete obj.data.vip_section;
        delete obj.data.vip_section_v2;
        delete obj.data.modular_vip_section;
        obj.data.vip_type = 2;
        if (obj.data.vip && obj.data.vip.status === 0) {
          obj.data.vip.status = 1;
          obj.data.vip.type = 2;
          obj.data.vip.due_date = 9005270400000;
          obj.data.vip.role = 15;
        }
        obj.data.sections_v2 = [
          {
            items: [
              { id: 396, title: "离线缓存", uri: "bilibili://user_center/download", icon: "http://i0.hdslb.com/bfs/feed-admin/9bd72251f7366c491cfe78818d453455473a9678.png", common_op_item: {}, mng_resource: { icon_id: 0, icon: "" } },
              { id: 397, title: "历史记录", uri: "bilibili://user_center/history", icon: "http://i0.hdslb.com/bfs/feed-admin/83862e10685f34e16a10cfe1f89dbd7b2884d272.png", common_op_item: {}, mng_resource: { icon_id: 0, icon: "" } },
              { id: 398, title: "我的收藏", uri: "bilibili://user_center/favourite", icon: "http://i0.hdslb.com/bfs/feed-admin/6ae7eff6af627590fc4ed80c905e9e0a6f0e8188.png", common_op_item: {}, mng_resource: { icon_id: 0, icon: "" } },
              { id: 399, title: "稍后再看", uri: "bilibili://user_center/watch_later", icon: "http://i0.hdslb.com/bfs/feed-admin/928ba9f559b02129e51993efc8afe95014edec94.png", common_op_item: {}, mng_resource: { icon_id: 0, icon: "" } }
            ],
            style: 1,
            button: {}
          },
          {
            items: [
              { id: 407, title: "联系客服", uri: "bilibili://user_center/feedback", icon: "http://i0.hdslb.com/bfs/feed-admin/7801a6180fb67cf5f8ee05a66a4668e49fb38788.png", common_op_item: {}, mng_resource: { icon_id: 0, icon: "" } },
              { id: 410, title: "设置", uri: "bilibili://user_center/setting", icon: "http://i0.hdslb.com/bfs/feed-admin/34e8faea00b3dd78977266b58d77398b0ac9410b.png", common_op_item: {}, mng_resource: { icon_id: 0, icon: "" } }
            ],
            style: 2,
            button: {}
          }
        ];
      }
    }

    // 3. 个人信息 VIP 状态
    else if (url.includes('/x/v2/account/myinfo')) {
      if (obj.data && obj.data.vip && obj.data.vip.status === 0) {
        obj.data.vip.status = 1;
        obj.data.vip.type = 2;
        obj.data.vip.due_date = 9005270400000;
        obj.data.vip.role = 15;
      }
    }

    // 4. 开屏广告秒跳
    else if (url.includes('/x/v2/splash/')) {
      if (obj.data) {
        delete obj.data.show;
        delete obj.data.event_list;
        delete obj.data.preload;
        delete obj.data.account;
        obj.data.show = [];
        obj.data.event_list = [];
        obj.data.max_time = 0;
        obj.data.min_interval = 31536000;
        obj.data.pull_interval = 31536000;
        if (Array.isArray(obj.data.list)) {
          for (let item of obj.data.list) {
            item.duration = 0;
            item.enable_pre_download = false;
            item.begin_time = 2208960000;
            item.end_time = 2209046399;
          }
        }
      }
    }

    // 5. 首页推荐流与 Story 去广告
    else if (url.includes('/x/v2/feed/index')) {
      if (url.includes('/story')) {
        if (obj.data && Array.isArray(obj.data.items)) {
          obj.data.items = obj.data.items.filter(item => {
            if (item.ad_info) return false;
            if (item.card_goto && /vertical_ad/i.test(item.card_goto)) return false;
            delete item.story_cart_icon;
            delete item.free_flow_toast;
            delete item.game_info;
            return true;
          });
        }
      } else {
        if (obj.data && Array.isArray(obj.data.items)) {
          obj.data.items = obj.data.items.filter(item => {
            if (item.banner_item) return false;
            if (item.ad_info) return false;
            if (item.card_type && /banner|cm/i.test(item.card_type)) return false;
            if (item.card_goto && item.card_goto !== 'av') return false;
            return true;
          });
        }
      }
    }

    // 6. 视频详情页横幅广告与相关推荐推广过滤【补全】
    else if (url.includes('/x/v2/view')) {
      if (obj.data) {
        delete obj.data.activity_banner;
        delete obj.data.activity_banner_info;
        delete obj.data.cm;
        delete obj.data.cm_config;
        delete obj.data.special_cell;
        obj.data.cms = [];
        if (Array.isArray(obj.data.relates)) {
          obj.data.relates = obj.data.relates.filter(r => {
            if (r.goto && r.goto !== 'av') return false;
            if (r.is_ad) return false;
            if (r.ad_info) return false;
            return true;
          });
        }
      }
    }

    // 7. 搜索页面推广广告视频过滤【补全】
    else if (url.includes('/x/v2/search')) {
      if (obj.data) {
        if (Array.isArray(obj.data.item)) {
          obj.data.item = obj.data.item.filter(i => {
            if (i.linktype && /_ad_?$/i.test(i.linktype)) return false;
            if (i.card_goto && /_?ad/i.test(i.card_goto)) return false;
            if (i.ad_info) return false;
            return true;
          });
        }
        if (Array.isArray(obj.data.items)) {
          obj.data.items = obj.data.items.filter(i => {
            if (i.linktype && /_ad_?$/i.test(i.linktype)) return false;
            if (i.card_goto && /_?ad/i.test(i.card_goto)) return false;
            if (i.ad_info) return false;
            return true;
          });
        }
      }
    }

    // 8. 皮肤装备去广告
    else if (url.includes('/x/resource/show/skin')) {
      if (obj.data && obj.data.common_equip) {
        delete obj.data.common_equip;
      }
    }

    // 9. 频道页面 Banner 广告过滤
    else if (url.includes('/pgc/page/channel')) {
      if (obj.data && Array.isArray(obj.data.modules)) {
        obj.data.modules = obj.data.modules.filter(m => m.type !== "TIP");
        for (let mod of obj.data.modules) {
          if (mod.type === "BANNER" && mod.module_data && Array.isArray(mod.module_data.items)) {
            mod.module_data.items = mod.module_data.items.filter(it => !it.url || !it.url.startsWith("https://www.bilibili.com/blackboard/era/"));
          }
        }
      }
    }

    body = JSON.stringify(obj);
  } catch (e) {
    // 异常安全回退
  }
}

$done({ body });

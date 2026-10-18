/**
 * 墨迹天气 净化脚本
 * 作用：过滤“我的”页面多余的工具区、灯泡和banner区商业推广
 */
let body = $response.body;
try {
  let obj = JSON.parse(body);
  if (obj && Array.isArray(obj.entrance_region_res_list)) {
    const blackList = ["工具区", "我页面灯泡", "banner区"];
    obj.entrance_region_res_list = obj.entrance_region_res_list.filter(
      item => item && !blackList.includes(item.region_name)
    );
    body = JSON.stringify(obj);
  }
} catch (e) {
  // 解析异常时保留原始内容，避免界面异常
}
$done({ body });

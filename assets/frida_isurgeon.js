/*
 * frida_isurgeon.js — 零重打包开锁：用 Surgeon 的合法契约注入 ISurgeon 实现
 *
 * 原理（已在 dex 层逐指令验证）：
 *   1) 每个被插桩的方法，方法头都是：
 *        sget-object v0, L<类>;->$surgeonFlag:Lcom/alibaba/surgeon/bridge/ISurgeon;
 *        const-string v1, "<id>"
 *        invoke-static {v0, v1}, Lcom/alibaba/surgeon/instrument/InstrumentAPI;->support(...)Z
 *        move-result v2
 *        if-eqz v2, :cond_XX          # support 为 false -> 走原实现
 *        ...  surgeon$dispatch("<id>", args) -> 直接 return
 *        :cond_XX  <原实现>
 *   2) InstrumentAPI.support(s, id) 的 smali：
 *        if-nez s, :cond_4 ; const/4 0 ; return 0        # s == null -> false
 *        :cond_4  invoke-interface s.surgeon$support(id) # 否则问实例
 *   3) 所以只要把 <类>->$surgeonFlag 从 null 换成我们的实现，该类所有插桩方法就都走我们。
 *      —— 不需要改 dex、不需要重打包、不需要改签名。
 *
 * 用法：
 *   frida -U -f com.alibaba.android.rimet.w2534344268 -l frida_isurgeon.js --no-pause
 *     （必须 spawn 模式：要赶在任何门控方法被调用之前装好 $surgeonFlag）
 *   只想看效果不想改行为：把 DRY_RUN 置 true。
 */

'use strict';

var DRY_RUN = false;

/* ------------------------------------------------------------------ *
 * 1) id -> 期望返回值
 *    类型码: Z=boolean  I=int  V=void(null)  N=null 对象
 *    全部来自 baksmali 反汇编核对的真实 id，见 tools/patches/data/surgeon_ids_gate.tsv
 * ------------------------------------------------------------------ */
var TABLE = {
  /* ---- ywm.a()  打开"开发者选项"入口（CommonSettingActivity:1729/1875、DeveloperOptionsActivity:129） ---- */
  '1669440712':  { t: 'Z', v: true },

  /* ---- Doraemon：一次性解锁所有 mode==1 门控 ---- */
  '-1919346692': { t: 'I', v: 1 },      // getRunningMode()I
  '1549858190':  { t: 'V', v: null },   // setRunningMode(I)V  -> no-op，防降级
  '787505523':   { t: 'V', v: null },   // setDebugMode(Z)V    -> no-op

  /* ---- DevSettingActivity 门控 ---- */
  '716893361':   { t: 'V', v: null },   // onCreate(Bundle)V -> 直接返回？不行！见下方 OVERRIDE_SKIP
  '1850914436':  { t: 'Z', v: true },   // E()  (= v1==0)
  '-1703260429': { t: 'I', v: 0 },      // ContactInterfaceImpl.e1() -> DevSettingActivity.v1

  /* ---- WebView / JSAPI 调试 ---- */
  '1621572248':  { t: 'Z', v: true },   // abg.b()  -> JSAPI debug 面板
  '-1335508869': { t: 'V', v: null },   // xz6.a(I)V

  /* ---- dev_setting 服务端开关链 ---- */
  '-769036951':  { t: 'Z', v: true },   // j35.e(String)  (ContactInterface.y0 -> "dev_setting")
  '-309150535':  { t: 'Z', v: true },   // j35.g(String,long,boolean)
  '1929703955':  { t: 'Z', v: true },   // j35.h(String,boolean)

  /* ---- 内测自动登录闸（BokuiActivity.p 的凭据注入路径） ---- */
  '-1007060566': { t: 'Z', v: true },   // q01.e()

  /* ---- SafeGuard：保持关闭，避免服务端开启后反噬 ---- */
  '1943258327':  { t: 'Z', v: false },  // AntiStrategyHandler.isGrayOpen()
  '-2011429551': { t: 'Z', v: false }   // AntiStrategyHandler.checkJsApiInvoke(...)
};

/* onCreate 不能靠 dispatch 直接 return —— 那会让界面永远空白。
 * 对这类"生命周期方法"，我们让 support() 返回 false，走原实现，再靠 mode/v1 的门控条件放行。 */
var OVERRIDE_SKIP = { '716893361': true };

/* ------------------------------------------------------------------ *
 * 2) 需要挂 $surgeonFlag 的类（全部来自 dex 实测）
 * ------------------------------------------------------------------ */
var TARGETS = [
  'ywm',                                                     // classes8
  'com.alibaba.doraemon.Doraemon',                            // classes14
  'com.alibaba.android.user.devset.DevSettingActivity',       // classes8
  'abg',                                                      // classes16
  'xz6',                                                      // classes30
  'j35',                                                      // classes8
  'q01',                                                      // classes4
  'com.alibaba.dingtalk.safeguard.AntiStrategyHandler'         // classes13
];

/* ------------------------------------------------------------------ */

function log(m) { console.log('[isurgeon] ' + m); }

Java.perform(function () {
  var BooleanCls = Java.use('java.lang.Boolean');
  var IntegerCls = Java.use('java.lang.Integer');
  var ISurgeon = Java.use('com.alibaba.surgeon.bridge.ISurgeon');

  var Proxy = Java.registerClass({
    name: 'io.research.SurgeonOverride',
    implements: [ISurgeon],
    methods: {
      'surgeon$support': function (id) {
        var hit = TABLE.hasOwnProperty(id) && !OVERRIDE_SKIP[id];
        if (DRY_RUN) { log('support(' + id + ') -> ' + hit); return false; }
        return hit;
      },
      'surgeon$dispatch': function (id, args) {
        var e = TABLE[id];
        if (!e) { log('dispatch(' + id + ') -> 未登记，返回 null'); return null; }
        if (DRY_RUN) { log('dispatch(' + id + ') -> ' + e.t + ':' + e.v); return null; }
        switch (e.t) {
          case 'Z': return BooleanCls.$new(e.v);
          case 'I': return IntegerCls.$new(e.v);
          case 'V': return null;
          default:  return e.v;
        }
      }
    }
  });

  var inst = Proxy.$new();
  log('ISurgeon 实现已构造: ' + inst);

  var ok = 0, miss = 0;
  TARGETS.forEach(function (name) {
    try {
      var K = Java.use(name);
      var f = K['$surgeonFlag'];
      if (!f) { log('!! ' + name + ' 没有 $surgeonFlag 字段（不是插桩类？）'); miss++; return; }
      f.value = inst;
      // 复核
      var now = K['$surgeonFlag'].value;
      log('OK  ' + name + '  $surgeonFlag = ' + (now === null ? 'null(失败)' : 'injected'));
      ok++;
    } catch (err) {
      log('!! ' + name + ' 装载失败: ' + err);
      miss++;
    }
  });
  log('完成: 注入 ' + ok + ' 个类, 失败 ' + miss + ' 个');

  /* 复核：直接读三个关键返回值 */
  try { log('ywm.a() = ' + Java.use('ywm').a()); } catch (e) {}
  try { log('Doraemon.getRunningMode() = ' + Java.use('com.alibaba.doraemon.Doraemon').getRunningMode()); } catch (e) {}
  try { log('abg.b() = ' + Java.use('abg').b()); } catch (e) {}
});

/* ------------------------------------------------------------------ *
 * 3) 兜底：万一某个类在 Java.perform 之后才被加载（多进程/插件 dex），
 *    用 ClassLoader hook 兜住。可选，默认不开。
 * ------------------------------------------------------------------ */
var HOOK_LOADER = false;
if (HOOK_LOADER) {
  Java.perform(function () {
    var BaseDexCl = Java.use('dalvik.system.BaseDexClassLoader');
    BaseDexCl.loadClass.overload('java.lang.String').implementation = function (n) {
      var c = this.loadClass(n);
      if (TARGETS.indexOf(n) >= 0) {
        try { Java.use(n)['$surgeonFlag'].value = Java.use('io.research.SurgeonOverride').$new(); } catch (e) {}
      }
      return c;
    };
  });
}

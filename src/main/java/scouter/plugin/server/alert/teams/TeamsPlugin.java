package scouter.plugin.server.alert.teams;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.*;
import org.apache.http.util.EntityUtils;

import scouter.lang.*;
import scouter.lang.counters.CounterConstants;
import scouter.lang.pack.*;
import scouter.lang.plugin.PluginConstants;
import scouter.lang.plugin.annotation.ServerPlugin;
import scouter.net.RequestCmd;
import scouter.server.*;
import scouter.server.core.AgentManager;
import scouter.server.db.TextRD;
import scouter.server.netio.AgentCall;
import scouter.util.DateUtil;
import scouter.util.HashUtil;

public class TeamsPlugin {

    final Configure conf = Configure.getInstance();
    private final MonitoringGroupConfigure groupConf;

    private static AtomicInteger ai = new AtomicInteger(0);
    private static List<Integer> javaeeObjHashList = new ArrayList<Integer>();
    private static AlertPack lastPack;
    private static long lastSentTimeStamp;

    public TeamsPlugin() {
        groupConf = new MonitoringGroupConfigure(conf);

        if (ai.incrementAndGet() == 1) {
            ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
            executor.scheduleAtFixedRate(new Runnable() {
                @Override
                public void run() {
                    if (conf.getInt("ext_plugin_thread_count_threshold", 0) == 0) return;
                    for (int objHash : javaeeObjHashList) {
                        try {
                            if (AgentManager.isActive(objHash)) {
                                ObjectPack objectPack = AgentManager.getAgent(objHash);
                                MapPack mapPack = new MapPack();
                                mapPack.put("objHash", objHash);
                                mapPack = AgentCall.call(objectPack, RequestCmd.OBJECT_THREAD_LIST, mapPack);

                                int thr = groupConf.getInt("ext_plugin_thread_count_threshold", objectPack.objType, 0);
                                int threadCount = mapPack.getList("name").size();

                                if (thr != 0 && threadCount > thr) {
                                    AlertPack ap = new AlertPack();
                                    ap.level = AlertLevel.WARN;
                                    ap.objHash = objHash;
                                    ap.title = "Thread count exceed a threshold.";
                                    ap.message = objectPack.objName + "'s Thread count(" + threadCount + ") exceed a threshold.";
                                    ap.time = System.currentTimeMillis();
                                    ap.objType = objectPack.objType;
                                    alert(ap);
                                }
                            }
                        } catch (Exception ignored) {}
                    }
                }
            }, 0, 5, TimeUnit.SECONDS);
        }
    }

    @ServerPlugin(PluginConstants.PLUGIN_SERVER_ALERT)
    public void alert(final AlertPack pack) {
        if (!groupConf.getBoolean("ext_plugin_teams_send_alert", pack.objType, false)) return;

        int level = groupConf.getInt("ext_plugin_teams_level", pack.objType, 0);
        if (level > pack.level) return;

        new Thread(() -> {
            try {
                String defaultWebhookURL = groupConf.getValue("ext_plugin_teams_webhook_url", pack.objType);
                String defaultChannel    = groupConf.getValue("ext_plugin_teams_channel", pack.objType);
                String defMentionsCsv    = groupConf.getValue("ext_plugin_teams_mention_users", pack.objType);

                if (isEmpty(defaultWebhookURL)) { println("[Teams] webhook URL is empty."); return; }

                String name = AgentManager.getAgentName(pack.objHash) == null ? "N/A" : AgentManager.getAgentName(pack.objHash);
                if ("N/A".equals(name) && pack.message != null && pack.message.endsWith("connected.")) {
                    int idx = pack.message.indexOf("connected");
                    name = pack.message.indexOf("reconnected") > -1 ? pack.message.substring(0, idx - 6) : pack.message.substring(0, idx - 4);
                }
                String title = pack.title;
                String msg   = pack.message == null ? "" : pack.message;
                if ("INACTIVE_OBJECT".equals(title)) {
                    title = "An object has been inactivated.";
                    msg = pack.message.substring(0, pack.message.indexOf("OBJECT") - 1);
                } else if ("ACTIVATED_OBJECT".equals(title)) {
                    title = "An object is activated now!!! ";
                    msg = pack.message.substring(0, pack.message.indexOf("OBJECT") - 1);
                }

                Routing routing = pickRouting(pack, name, title, msg, defaultWebhookURL, defaultChannel, defMentionsCsv);
                if (isEmpty(routing.webhookURL)) { println("[Teams] webhook URL is empty after routing."); return; }

                // 전역(관리자) 멘션 + 팬아웃
                List<Mention> globalMentions = parseMentionsCsv(conf.getValue("ext_plugin_teams_global_mentions"));
                routing.mentions = mergeMentions(routing.mentions, globalMentions);
                List<String> fanoutUrls = parseCsv(conf.getValue("ext_plugin_teams_global_webhook_urls"));

                // 중복 억제(1시간)
                if (groupConf.getBoolean("ext_plugin_ignore_duplicate_alert", pack.objType,false) && lastPack != null) {
                    long diff = System.currentTimeMillis() - lastSentTimeStamp;
                    if (lastPack.objHash == pack.objHash && lastPack.title.equals(pack.title) && diff < DateUtil.MILLIS_PER_HOUR) {
                        println("ignored duplicate alert for an hour : " + pack.title);
                        return;
                    }
                }

                String payload = makeAdaptiveCardMessage(
                        name,
                        safeUpper(pack.objType),
                        title,
                        msg,
                        routing.mentions
                );

                if (groupConf.getBoolean("ext_plugin_teams_debug", pack.objType, false)) {
                    println("Primary WebHookURL : " + routing.webhookURL);
                    if (!fanoutUrls.isEmpty()) println("Fanout WebHookURLs : " + fanoutUrls);
                    println("payload : " + payload);
                }

                sendWebhook(routing.webhookURL, payload, routing.channel);
                for (String url : fanoutUrls) sendWebhook(url, payload, "fanout");

                lastSentTimeStamp = System.currentTimeMillis();
                lastPack = pack;

            } catch (Exception e) {
                println("[Error] : " + e.getMessage());
                if (conf._trace) e.printStackTrace();
            }
        }).start();
    }

    private void sendWebhook(String url, String payload, String channelLogName) throws Exception {
        HttpPost post = new HttpPost(url);
        post.setHeader("Content-Type", "application/json; charset=UTF-8");
        post.setEntity(new StringEntity(payload, ContentType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8)));
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpResponse response = client.execute(post);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                println("Teams message sent to [" + channelLogName + "] successfully.");
            } else {
                println("Teams message sent failed. Verify below information.");
                println("[WebHookURL] : " + url);
                println("[Reason] : " + EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
            }
        }
    }

    // ===== OBJECT =====
    @ServerPlugin(PluginConstants.PLUGIN_SERVER_OBJECT)
    public void object(ObjectPack pack) {
        if (!conf.getBoolean("ext_plugin_teams_object_alert_enabled", false)) return;
        if (pack.version != null && pack.version.length() > 0) {
            AlertPack ap = null;
            ObjectPack op = AgentManager.getAgent(pack.objHash);
            if (op == null && pack.wakeup == 0L) {
                ap = new AlertPack();
                ap.level = AlertLevel.INFO; ap.objHash = pack.objHash;
                ap.title = "An object has been activated.";
                ap.message = pack.objName + " is connected.";
                ap.time = System.currentTimeMillis();
                ap.objType = (AgentManager.getAgent(pack.objHash) != null) ? AgentManager.getAgent(pack.objHash).objType : "scouter";
                alert(ap);
            } else if (op != null && !op.alive) {
                ap = new AlertPack();
                ap.level = AlertLevel.INFO; ap.objHash = pack.objHash;
                ap.title = "An object has been activated.";
                ap.message = pack.objName + " is reconnected.";
                ap.time = System.currentTimeMillis();
                ap.objType = AgentManager.getAgent(pack.objHash).objType;
                alert(ap);
            }
        }
    }

    // ===== XLOG (널 세이프 + 사용자 라우팅 유지: WINGS 포함) =====
    @ServerPlugin(PluginConstants.PLUGIN_SERVER_XLOG)
    public void xlog(XLogPack pack) {
        try {
            if (!conf.getBoolean("ext_plugin_teams_xlog_enabled", false)) return;
            if (pack == null) { println("[xlog] pack is null"); return; }

            ObjectPack agent = AgentManager.getAgent(pack.objHash);
            String objType = (agent != null && agent.objType != null) ? agent.objType : "scouter";

            if (!groupConf.getBoolean("ext_plugin_teams_xlog_enabled", objType, true)) return;

            if (pack.error != 0) {
                String date = DateUtil.yyyymmdd(pack.endTime);
                String service = safeGet(() -> TextRD.getString(date, TextTypes.SERVICE, pack.service), String.valueOf(pack.service));
                String errText = safeGet(() -> TextRD.getString(date, TextTypes.ERROR, pack.error), String.valueOf(pack.error));

                AlertPack ap = new AlertPack();
                ap.level = AlertLevel.ERROR; ap.objHash = pack.objHash;
                ap.title = "xlog Error";
                ap.message = "URL  :  " + service + " \r\n\r\n Error_Message  :  " + errText;
                ap.time = System.currentTimeMillis(); ap.objType = objType;

                String name = AgentManager.getAgentName(pack.objHash);
                if (name == null) name = "N/A";

                if ("/cjescwas01/escprd1".equals(name) || "/cjescwas02/escprd2".equals(name) || "/cjescwasdev/escdev".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_esc_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas03/expwas01".equals(name) || "/cjwas04/expwas02".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_exp_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas03/igap_was3".equals(name) || "/cjwas04/igap_was4".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_igap_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas03/tmsprd1-1".equals(name) || "/cjwas03/tmsprd1-2".equals(name) || "/cjwas04/tmsprd2-1".equals(name) || "/cjwas04/tmsprd2-2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_tms_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/gprtwas1/wise_prd11".equals(name) || "/gprtwas1/wise_prd12".equals(name) || "/gprtwas2/wise_prd21".equals(name) || "/gprtwas2/wise_prd22".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_wise_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas03/mproWas03".equals(name) || "/cjwas04/mproWas04".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_mpro_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas01/cis1".equals(name) || "/cjwas02/cis2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_cis_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjodswas01/odsprd01".equals(name) || "/cjodswas02/odsprd02".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_ods_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjpcplwas1/cplwas1".equals(name) || "/cjpcplwas2/cplwas2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_cpl_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas03/qmswas1".equals(name) || "/cjwas04/qmswas2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_qms_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjirisap1/bmis_was1".equals(name) || "/cjemap/bmis_was2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_bmis_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjirisap1/iris_was1".equals(name) || "/cjemap/iris_was2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_iris_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/pEacA1/PFLS_LIVE1".equals(name) || "/pEacA2/PFLS_LIVE2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_pfls_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas03/amsprd_1".equals(name) || "/cjwas04/cmsprd_2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_ams_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwas03/cmsprd_1".equals(name) || "/cjwas04/cmsprd_2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_cms_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cjwingswas01/WINGS_PRD1-1".equals(name) || "/cjwingswas01/WINGS_PRD1-2".equals(name) || "/cjwingswas02/WINGS_PRD2-1".equals(name) || "/cjwingswas02/WINGS_PRD2-2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_hanaro_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/CJHANAROWAS01/HANARO_PRD1".equals(name) || "/CJHANAROWAS02/HANARO_PRD2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_hanaro_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/cj-meta-app/cj-meta-app".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_meta_teams_xlog_enabled", objType, false )) alert(ap);
                } else if("/CJFPAAP/fta".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_fta_teams_xlog_enabled", objType, false )) alert(ap);
                } else {
                    alert(ap);
                }
            }

            try {
                int elapsedThreshold = groupConf.getInt("ext_plugin_elapsed_time_threshold", objType, 0);
                if (elapsedThreshold != 0 && pack.elapsed > elapsedThreshold) {
                    String serviceName = safeGet(() -> TextRD.getString(DateUtil.yyyymmdd(pack.endTime), TextTypes.SERVICE, pack.service),
                                                 String.valueOf(pack.service));
                    AlertPack ap = new AlertPack();
                    ap.level = AlertLevel.WARN; ap.objHash = pack.objHash;
                    ap.title = "Elapsed Time Exceed a threshold.";
                    ap.message = "[" + safe(AgentManager.getAgentName(pack.objHash)) + "] "
                            + "  [URL : "+ serviceName + "] "
                            + "  Elapsed Time(" + pack.elapsed + " ms) exceed a threshold.";
                    ap.time = System.currentTimeMillis(); ap.objType = objType;
                    alert(ap);
                }
            } catch (Throwable t) { println("[xlog elapsed] error: " + t); }

        } catch (Throwable t) {
            println("[xlog] unhandled error: " + t);
            Logger.printStackTrace(t);
        }
    }

    // ===== COUNTER =====
    @ServerPlugin(PluginConstants.PLUGIN_SERVER_COUNTER)
    public void counter(PerfCounterPack pack) {
        String objName = pack.objName;
        int objHash = HashUtil.hash(objName);
        String objType = null;
        String objFamily = null;

        if (AgentManager.getAgent(objHash) != null) {
            objType = AgentManager.getAgent(objHash).objType;
        }

        if (objType != null) {
            objFamily = CounterManager.getInstance().getCounterEngine().getObjectType(objType).getFamily().getName();
        }

        try {
            if (CounterConstants.FAMILY_JAVAEE.equals(objFamily)) {
                if (!javaeeObjHashList.contains(objHash)) {
                    javaeeObjHashList.add(objHash);
                }

                if (pack.timetype == TimeTypeEnum.REALTIME) {
                    long gcTimeThreshold = groupConf.getLong("ext_plugin_gc_time_threshold", objType, 0);
                    long gcTime = pack.data.getLong(CounterConstants.JAVA_GC_TIME);

                    long heapUsedThreshold = conf.getLong("ext_plugin_heap_used_threshold", 0);
                    long heapUsedThreshold_8G = conf.getLong("ext_plugin_8G_heap_used_threshold", 0);
                    long heapUsedThreshold_6G = conf.getLong("ext_plugin_6G_heap_used_threshold", 0);
                    long heapUsedThreshold_4G = conf.getLong("ext_plugin_4G_heap_used_threshold", 0);
                    long heapUsed = pack.data.getLong(CounterConstants.JAVA_HEAP_USED);

                    long thresholdToUse = getHeapThresholdForServer(objName, heapUsedThreshold, heapUsedThreshold_8G, heapUsedThreshold_6G, heapUsedThreshold_4G);
                    
                    if (thresholdToUse != 0 && heapUsed > thresholdToUse) {
                        AlertPack ap = new AlertPack();
                        ap.level = AlertLevel.FATAL;
                        ap.objHash = objHash;
                        ap.title = "Heap used exceed a threshold.";
                        ap.message = objName + " Heap used(" + heapUsed + " M) exceed a threshold.";
                        ap.time = System.currentTimeMillis();
                        ap.objType = objType;
                        alert(ap);
                    }

                    if (gcTimeThreshold != 0 && gcTime > gcTimeThreshold) {
                        AlertPack ap = new AlertPack();
                        ap.level = AlertLevel.WARN; ap.objHash = objHash;
                        ap.title = "GC time exceed a threshold.";
                        ap.message = objName + "'s GC time(" + gcTime + " ms) exceed a threshold.";
                        ap.time = System.currentTimeMillis(); 
                        ap.objType = objType;
                        alert(ap);
                    }
                }
            }
        } catch (Exception e) { Logger.printStackTrace(e); }
    }

    private void println(Object o) {
        if (conf.getBoolean("ext_plugin_teams_debug", false)) {
            System.out.println(o);
            Logger.println(o);
        }
    }

    // ===== 멘션 모델 & 라우팅 =====
    static class Mention {
        String id;       // UPN 또는 AAD Object Id
        String display;  // 표기(별칭)
        Mention(String id, String display) { this.id = id; this.display = display; }
    }
    static class Routing {
        String webhookURL;
        String channel;
        List<Mention> mentions = new ArrayList<>();
    }

    private Routing pickRouting(AlertPack pack, String agentName, String title, String msg,
                                String defUrl, String defChannel, String defMentionsCsv) {
        Routing r = new Routing();
        r.webhookURL = defUrl;
        r.channel    = defChannel;
        r.mentions   = parseMentionsCsv(defMentionsCsv);

        String rulesCsv = conf.getValue("ext_plugin_teams_rules");
        if (isEmpty(rulesCsv)) return r;

        String haystack = (safe(agentName) + " | " + safe(pack.objType) + " | " + safe(title) + " | " + safe(msg)).toLowerCase(Locale.ROOT);

        for (String raw : rulesCsv.split(",")) {
            String key = safe(raw).trim();
            if (key.isEmpty()) continue;

            String cond = conf.getValue("ext_plugin_teams_rule." + key + ".when.contains");
            if (isEmpty(cond)) continue;

            boolean matched = false;
            if ("*".equals(cond.trim())) {
                matched = true;
            } else {
                for (String token : cond.split("\\|")) {
                    String t = safe(token).toLowerCase(Locale.ROOT).trim();
                    if (!t.isEmpty() && haystack.contains(t)) { matched = true; break; }
                }
            }

            if (matched) {
                String url = conf.getValue("ext_plugin_teams_rule." + key + ".webhook_url");
                String ch  = conf.getValue("ext_plugin_teams_rule." + key + ".channel");
                String men = conf.getValue("ext_plugin_teams_rule." + key + ".mentions");

                if (!isEmpty(url)) r.webhookURL = url.trim();
                if (!isEmpty(ch))  r.channel    = ch.trim();
                if (men != null)   r.mentions   = parseMentionsCsv(men);
                break;
            }
        }
        return r;
    }

    // ===== Adaptive Card + 맨션 (텍스트/엔티티 완전 일치, v1.2) =====
    private String makeAdaptiveCardMessage(String serverName, String type, String title, String msg, List<Mention> mentions) {
        serverName = safe(serverName);
        type = safe(type);
        title = safe(title);
        msg = safe(msg);

        StringBuilder body = new StringBuilder();
        body.append("{\"type\":\"TextBlock\",\"weight\":\"Bolder\",\"size\":\"Medium\",\"text\":\"")
            .append(escJson("[" + type + "] " + title)).append("\"}");

        boolean hasMentions = mentions != null && !mentions.isEmpty();
        StringBuilder entities = new StringBuilder();

        if (hasMentions) {
            StringBuilder mentionLine = new StringBuilder("알림: ");
            entities.append("[");

            int count = 0;
            for (Mention m : mentions) {
                if (m == null || isEmpty(m.id)) continue;

                String disp = normalizeAlias(safe(m.display)); // ★ 한글 깨짐 자동 복구
                String id   = safe(m.id).trim();               // upn 또는 aad id

                if (count > 0) {
                    mentionLine.append(", ");
                    entities.append(",");
                }
                String atToken = "<at>" + disp + "</at>"; // 본문과 엔티티 text를 "완전히 동일"하게
                mentionLine.append(atToken);

                entities.append("{")
                        .append("\"type\":\"mention\",")
                        .append("\"text\":\"").append(escJson(atToken)).append("\",")
                        .append("\"mentioned\":{")
                           .append("\"id\":\"").append(escJson(id)).append("\",")
                           .append("\"name\":\"").append(escJson(disp)).append("\"")
                        .append("}")
                        .append("}");
                count++;
            }
            entities.append("]");

            body.append(",{")
                .append("\"type\":\"TextBlock\",\"wrap\":true,")
                .append("\"text\":\"").append(escJson(mentionLine.toString())).append("\"")
                .append("}");
        }

        String detail = "[SERVER] : " + serverName + "\n\n[MESSAGE] : \n\n" + msg;

        body.append(",{\"type\":\"TextBlock\",\"wrap\":true,\"text\":\"")
            .append(escJson(detail)).append("\"}");

        StringBuilder card = new StringBuilder();
        card.append("{")
            .append("\"type\":\"message\",")
            .append("\"attachments\":[{")
              .append("\"contentType\":\"application/vnd.microsoft.card.adaptive\",")
              .append("\"content\":{")
                .append("\"$schema\":\"http://adaptivecards.io/schemas/adaptive-card.json\",")
                .append("\"type\":\"AdaptiveCard\",\"version\":\"1.2\",") // 호환성↑
                .append("\"body\":[")
                  .append(body)
                .append("]");

        if (hasMentions) {
            card.append(",\"msteams\":{\"entities\":").append(entities).append("}");
        }

        card.append("}}]}");
        return card.toString();
    }

    // ===== helpers =====
    private static String safe(String s) { return s == null ? "" : s; }
    private static boolean isEmpty(String s) { return s == null || s.trim().isEmpty(); }
    private static String safeUpper(String s) { return s == null ? "" : s.toUpperCase(Locale.ROOT); }
    private static String escJson(String s) { if (s == null) return ""; return s.replace("\\","\\\\").replace("\"","\\\""); }

    // CSV → List<String>
    private static List<String> parseCsv(String csv) {
        List<String> out = new ArrayList<>();
        if (csv == null || csv.trim().isEmpty()) return out;
        for (String t : csv.split(",")) {
            if (t == null) continue;
            String v = t.trim();
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }

    // "id|별칭" 또는 "id"
    private List<Mention> parseMentionsCsv(String csv) {
        List<Mention> out = new ArrayList<>();
        if (isEmpty(csv)) return out;

        for (String token : csv.split(",")) {
            if (token == null) continue;
            String t = token.trim();
            if (t.isEmpty()) continue;

            String id = t;
            String aliasInline = null;

            int p = t.indexOf('|');
            if (p > -1) {
                id = t.substring(0, p).trim();
                aliasInline = t.substring(p + 1).trim();
            }

            // 별칭은 항상 정규화(한글 깨짐 자동 복구)
            String display = normalizeAlias(isEmpty(aliasInline) ? id : aliasInline);
            out.add(new Mention(id, display));
        }
        return out;
    }

    // 멘션 병합(중복 id 제거, 기존 표시명 우선)
    private List<Mention> mergeMentions(List<Mention> a, List<Mention> b) {
        if ((a == null || a.isEmpty()) && (b == null || b.isEmpty())) return new ArrayList<>();
        Map<String, Mention> map = new LinkedHashMap<>();
        if (a != null) for (Mention m : a) if (m != null && m.id != null) map.put(m.id.toLowerCase(Locale.ROOT), m);
        if (b != null) for (Mention m : b) {
            if (m == null || m.id == null) continue;
            String k = m.id.toLowerCase(Locale.ROOT);
            if (!map.containsKey(k)) map.put(k, m);
        }
        return new ArrayList<>(map.values());
    }

    // ===== 별칭 한글 깨짐 근본 복구 =====

    // 1) uXXXX 유니코드 이스케이프를 실제 문자로
    private static final Pattern UNICODE_ESC = Pattern.compile("\\\\u([0-9a-fA-F]{4})");
    private String unescapeUnicode(String s) {
        if (isEmpty(s)) return s;
        StringBuffer sb = new StringBuffer();
        Matcher m = UNICODE_ESC.matcher(s);
        while (m.find()) {
            char ch = (char) Integer.parseInt(m.group(1), 16);
            m.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf(ch)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // 2) ISO-8859-1로 잘못 디코드된 문자열을 UTF-8로 복구
    private String recoverIsoToUtf8(String s) {
        if (isEmpty(s)) return s;
        try {
            byte[] iso = s.getBytes("ISO-8859-1");
            return new String(iso, StandardCharsets.UTF_8);
        } catch (Exception ignore) {
            return s;
        }
    }

    // 3) 한글 글자 수 세기 (완성형/자모 포함)
    private int scoreHangul(String s) {
        if (isEmpty(s)) return 0;
        int score = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 0xAC00 && c <= 0xD7AF) || (c >= 0x1100 && c <= 0x11FF) || (c >= 0x3130 && c <= 0x318F)) {
                score++;
            }
        }
        return score;
    }

    // 4) 별칭 정규화: 원문 / 유니코드 해제 / ISO→UTF-8 복구 중 한글 스코어가 가장 높은 후보 선택
    private String normalizeAlias(String s) {
        String a = safe(s).trim();
        String b = unescapeUnicode(a);
        String c = recoverIsoToUtf8(a);

        int sa = scoreHangul(a);
        int sb = scoreHangul(b);
        int sc = scoreHangul(c);

        String best = a;
        int bestScore = sa;

        if (sb > bestScore) { best = b; bestScore = sb; }
        if (sc > bestScore) { best = c; bestScore = sc; }

        // 동률이면 더 읽기 좋은(길이 긴) 후보
        if (bestScore == sa && bestScore == sb && bestScore == sc) {
            if (b.length() > best.length()) best = b;
            if (c.length() > best.length()) best = c;
        }
        return best;
    }

    // 안전 호출 유틸
    private static <T> T safeGet(SupplierWithEx<T> sup, T fallback) {
        try { return sup.get(); } catch (Throwable t) { return fallback; }
    }

    // 메모리 서버 그룹
    private long getHeapThresholdForServer(String objName, long defaultThreshold, long threshold8G, long threshold6G, long threshold4G) {
        String servers8G = conf.getValue("ext_plugin_heap_8g_servers", "/gprtwas1/wise_prd11,/gprtwas1/wise_prd12,/gprtwas2/wise_prd21,/gprtwas2/wise_prd22");
        String servers6G = conf.getValue("ext_plugin_heap_6g_servers", "/pEacA1/PFLS_LIVE1,/pEacA2/PFLS_LIVE2");
        String servers4G = conf.getValue("ext_plugin_heap_4g_servers", "/cjwas03/expwas01,/cjwas04/expwas02,/cjwas03/qmswas1,/cjwas04/qmswas2,/cjwas03/amsprd_1,/cjwas04/amsprd_2,/cjwas03/cmsprd_1,/cjwas04/cmsprd_2,/cjirisap1/bmis_was1,/cjirisap1/iris_was1,/cjemap/bmis_was2,/cjemap/iris_was2");
        
        if (isServerInList(objName, servers8G)) {
            return threshold8G;
        } else if (isServerInList(objName, servers6G)) {
            return threshold6G;
        } else if (isServerInList(objName, servers4G)) {
            return threshold4G;
        } else {
            return defaultThreshold;
        }
    }
    
    private boolean isServerInList(String objName, String serverList) {
        if (isEmpty(serverList)) return false;
        String[] servers = serverList.split(",");
        for (String server : servers) {
            if (server.trim().equals(objName)) {
                return true;
            }
        }
        return false;
    }

    @FunctionalInterface
    interface SupplierWithEx<T> { T get() throws Exception; }
}

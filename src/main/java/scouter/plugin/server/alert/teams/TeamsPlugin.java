package scouter.plugin.server.alert.teams;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import scouter.lang.AlertLevel;
import scouter.lang.TextTypes;
import scouter.lang.TimeTypeEnum;
import scouter.lang.counters.CounterConstants;
import scouter.lang.pack.AlertPack;
import scouter.lang.pack.MapPack;
import scouter.lang.pack.ObjectPack;
import scouter.lang.pack.PerfCounterPack;
import scouter.lang.pack.XLogPack;
import scouter.lang.plugin.PluginConstants;
import scouter.lang.plugin.annotation.ServerPlugin;
import scouter.net.RequestCmd;
import scouter.server.Configure;
import scouter.server.CounterManager;
import scouter.server.Logger;
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

            // thread count check
            executor.scheduleAtFixedRate(new Runnable() {
                @Override
                public void run() {
                    if (conf.getInt("ext_plugin_thread_count_threshold", 0) == 0) {
                        return;
                    }
                    for (int objHash : javaeeObjHashList) {
                        try {
                            if (AgentManager.isActive(objHash)) {
                                ObjectPack objectPack = AgentManager.getAgent(objHash);
                                MapPack mapPack = new MapPack();
                                mapPack.put("objHash", objHash);

                                mapPack = AgentCall.call(objectPack, RequestCmd.OBJECT_THREAD_LIST, mapPack);

                                int threadCountThreshold = groupConf.getInt("ext_plugin_thread_count_threshold", objectPack.objType, 0);
                                int threadCount = mapPack.getList("name").size();

                                if (threadCountThreshold != 0 && threadCount > threadCountThreshold) {
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
                        } catch (Exception e) {
                            // ignore
                        }
                    }
                }
            },
            0, 5, TimeUnit.SECONDS);
        }
    }

    @ServerPlugin(PluginConstants.PLUGIN_SERVER_ALERT)
    public void alert(final AlertPack pack) {
        if (groupConf.getBoolean("ext_plugin_teams_send_alert", pack.objType, false)) {
            int level = groupConf.getInt("ext_plugin_teams_level", pack.objType, 0);
            // Get log level (0 : INFO, 1 : WARN, 2 : ERROR, 3 : FATAL)
            if (level <= pack.level) {
                new Thread() {
                    public void run() {
                        try {
                            // https://cjworld.webhook.office.com/webhookb2/547d96eb-3d0e-4d56-aa8f-8164946e6a93@ee6af5c5-684f-4539-9eb6-64793af08027/IncomingWebhook/fdf6b83ecd54438491f239973eef897d/7424369a-02ba-469f-8a14-5c90eb8766b8
                            String webhookURL = groupConf.getValue("ext_plugin_teams_webhook_url", pack.objType);
                            // General
                            String channel = groupConf.getValue("ext_plugin_teams_channel", pack.objType);

                            assert webhookURL != null;

                            // Get the agent Name
                            String name = AgentManager.getAgentName(pack.objHash) == null ? "N/A" : AgentManager.getAgentName(pack.objHash);

                            if (name.equals("N/A") && pack.message.endsWith("connected.")) {
                                int idx = pack.message.indexOf("connected");
                                if (pack.message.indexOf("reconnected") > -1) {
                                    name = pack.message.substring(0, idx - 6);
                                } else {
                                    name = pack.message.substring(0, idx - 4);
                                }
                            }

                            String title = pack.title;
                            String msg = pack.message;
                            if (title.equals("INACTIVE_OBJECT")) {
                                title = "An object has been inactivated.";
                                msg = pack.message.substring(0, pack.message.indexOf("OBJECT") - 1);
                            } else if (title.equals("ACTIVATED_OBJECT")) {
                                title = "An object is activated now!!! ";
                                msg = pack.message.substring(0, pack.message.indexOf("OBJECT") - 1);
                            }
                            
                            String finalMsg = makeMessage(name, pack.objType.toUpperCase(), title, msg);

                            if (groupConf.getBoolean("ext_plugin_ignore_duplicate_alert", pack.objType,false) && lastPack != null){
                                long diff = System.currentTimeMillis() - lastSentTimeStamp;
                                if (lastPack.objHash == pack.objHash && lastPack.title.equals(pack.title) && diff < DateUtil.MILLIS_PER_HOUR) {
                                    println("ignored continuous duplicate alert for an hour  : " + pack.title);
                                    return;
                                }
                            }

                            if (groupConf.getBoolean("ext_plugin_teams_debug", pack.objType, false)) {
                                println("WebHookURL : " + webhookURL);
                                println("param : " + finalMsg);
                            }

                            HttpPost post = new HttpPost(webhookURL);
                            post.addHeader("Content-Type", "application/json");
                            // charset set utf-8
                            post.setEntity(new StringEntity(finalMsg, "utf-8"));

                            CloseableHttpClient client = HttpClientBuilder.create().build();

                            // send the post request
                            HttpResponse response = client.execute(post);

                            // save the last pack info to ignore continuous duplicate alert
                            lastSentTimeStamp = System.currentTimeMillis();
                            lastPack = pack;

                            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                                println("Teams message sent to [Channel : " + channel + "] successfully.");
                            } else {
                                println("Teams message sent failed. Verify below information.");
                                println("[WebHookURL] : " + webhookURL);
                                println("[Message] : " + finalMsg);
                                println("[Reason] : " + EntityUtils.toString(response.getEntity(), "UTF-8"));
                            }
                        } catch (Exception e) {
                            println("[Error] : " + e.getMessage());
                            if (conf._trace) {
                                e.printStackTrace();
                            }
                        }
                    }

                }.start();
            }
        }
    }

    @ServerPlugin(PluginConstants.PLUGIN_SERVER_OBJECT)
    public void object(ObjectPack pack) {
        if (!conf.getBoolean("ext_plugin_teams_object_alert_enabled", false)) {
            return;
        }

        if (pack.version != null && pack.version.length() > 0) {
            AlertPack ap = null;
            ObjectPack op = AgentManager.getAgent(pack.objHash);

            if (op == null && pack.wakeup == 0L) {
                // in case of new agent connected
                ap = new AlertPack();
                ap.level = AlertLevel.INFO;
                ap.objHash = pack.objHash;
                ap.title = "An object has been activated.";
                ap.message = pack.objName + " is connected.";
                ap.time = System.currentTimeMillis();

                if (AgentManager.getAgent(pack.objHash) != null) {
                    ap.objType = AgentManager.getAgent(pack.objHash).objType;
                } else {
                    ap.objType = "scouter";
                }

                alert(ap);
            } else if (op.alive == false) {
                // in case of agent reconnected
                ap = new AlertPack();
                ap.level = AlertLevel.INFO;
                ap.objHash = pack.objHash;
                ap.title = "An object has been activated.";
                ap.message = pack.objName + " is reconnected.";
                ap.time = System.currentTimeMillis();
                ap.objType = AgentManager.getAgent(pack.objHash).objType;

                alert(ap);
            }
            // inactive state can be handled in alert() method.
        }
    }

    @ServerPlugin(PluginConstants.PLUGIN_SERVER_XLOG)
    public void xlog(XLogPack pack) {
        if (!conf.getBoolean("ext_plugin_teams_xlog_enabled", false)) {
            return;
        }

        String objType = AgentManager.getAgent(pack.objHash).objType;
        if (groupConf.getBoolean("ext_plugin_teams_xlog_enabled", objType, true)) {
            if (pack.error != 0) {
                String date = DateUtil.yyyymmdd(pack.endTime);
                String service = TextRD.getString(date, TextTypes.SERVICE, pack.service);

                AlertPack ap = new AlertPack();
                ap.level = AlertLevel.ERROR;
                ap.objHash = pack.objHash;
                ap.title = "xlog Error";
                ap.message = "URL  :  "+service + " \r\n\r\n Error_Message  :  " + TextRD.getString(date, TextTypes.ERROR, pack.error);
                ap.time = System.currentTimeMillis();
                ap.objType = objType;
                // alert(ap);

                // Get agent Name
                String name = AgentManager.getAgentName(pack.objHash) == null ? "N/A" : (String) AgentManager.getAgentName(pack.objHash);

                if ("/cjescwas01/escprd1".equals(name) || "/cjescwas02/escprd2".equals(name) || "/cjescwasdev/escdev".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_esc_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjwas03/expwas01".equals(name) || "/cjwas04/expwas02".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_exp_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjwas03/igap_was3".equals(name) || "/cjwas04/igap_was4".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_igap_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjwas03/tmsprd1-1".equals(name) || "/cjwas03/tmsprd1-2".equals(name) || "/cjwas04/tmsprd2-1".equals(name) || "/cjwas04/tmsprd2-2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_tms_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/gprtwas1/wise_prd11".equals(name) || "/gprtwas1/wise_prd12".equals(name) || "/gprtwas2/wise_prd21".equals(name) || "/gprtwas2/wise_prd22".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_wise_teams_xlog_enabled", objType, false )) {
                        alert(ap);
                    }
                } else if("/cjwas03/mproWas03".equals(name) || "/cjwas04/mproWas04".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_mpro_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjwas01/cis1".equals(name) || "/cjwas02/cis2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_cis_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjodswas01/odsprd01".equals(name) || "/cjodswas02/odsprd02".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_ods_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjpcplwas1/cplwas1".equals(name) || "/cjpcplwas2/cplwas2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_cpl_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjwas03/qmswas1".equals(name) || "/cjwas04/qmswas2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_qms_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjirisap1/bmis_was1".equals(name) || "/cjemap/bmis_was2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_bmis_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjirisap1/iris_was1".equals(name) || "/cjemap/iris_was2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_iris_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/pEacA1/PFLS_LIVE1".equals(name) || "/pEacA2/PFLS_LIVE2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_pfls_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjwas03/amsprd_1".equals(name) || "/cjwas04/amsprd_2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_ams_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/cjwas03/cmsprd_1".equals(name) || "/cjwas04/cmsprd_2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_cms_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/CJHANAROWAS01/HANARO_PRD1".equals(name) || "/CJHANAROWAS02/HANARO_PRD2".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_hanaro_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                }else if("/cj-meta-app/cj-meta-app".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_meta_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else if("/CJFPAAP/fta".equals(name)) {
                    if (groupConf.getBoolean("ext_plugin_fta_teams_xlog_enabled", objType, false )){
                        alert(ap);
                    }
                } else {
                    alert(ap);
                }
            }

            try {
                int elapsedThreshold = groupConf.getInt("ext_plugin_elapsed_time_threshold", objType, 0);

                if (elapsedThreshold != 0 && pack.elapsed > elapsedThreshold) {
                    String serviceName = TextRD.getString(DateUtil.yyyymmdd(pack.endTime), TextTypes.SERVICE, pack.service);

                    AlertPack ap = new AlertPack();

                    ap.level = AlertLevel.WARN;
                    ap.objHash = pack.objHash;
                    ap.title = "Elapsed Time Exceed a threshold.";
                    ap.message = "[" + AgentManager.getAgentName(pack.objHash) + "] "
                            + "  [URL : "+ serviceName + "] "
                            + "  Elapsed Time(" + pack.elapsed + " ms) exceed a threshold.";
                    ap.time = System.currentTimeMillis();
                    ap.objType = objType;

                    alert(ap);
                }

            } catch (Exception e) {
                Logger.printStackTrace(e);
            }
        }
    }


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
            // in case of objFamily is javaee
            if (CounterConstants.FAMILY_JAVAEE.equals(objFamily)) {
                // save javaee type's objHash
                if (!javaeeObjHashList.contains(objHash)) {
                    javaeeObjHashList.add(objHash);
                }

                if (pack.timetype == TimeTypeEnum.REALTIME) {
                    long gcTimeThreshold = groupConf.getLong("ext_plugin_gc_time_threshold", objType, 0);
                    long gcTime = pack.data.getLong(CounterConstants.JAVA_GC_TIME);

                    if (gcTimeThreshold != 0 && gcTime > gcTimeThreshold) {
                        AlertPack ap = new AlertPack();

                        ap.level = AlertLevel.WARN;
                        ap.objHash = objHash;
                        ap.title = "GC time exceed a threshold.";
                        ap.message = objName + "'s GC time(" + gcTime + " ms) exceed a threshold.";
                        ap.time = System.currentTimeMillis();
                        ap.objType = objType;

                        alert(ap);
                    }
                }
            }
        } catch (Exception e) {
            Logger.printStackTrace(e);
        }
    }

    private void println(Object o) {
        if (conf.getBoolean("ext_plugin_teams_debug", false)) {
            System.out.println(o);
            Logger.println(o);
        }
    }

    /* private String makeMessage(String serverName, String type, String title, String msg) {
        StringBuilder template = new StringBuilder();
        template.append("{");
        template.append("\"@type\": \"MessageCard\",");
        template.append("\"@context\": \"https://schema.org/extensions\",");
        template.append("\"title\": \"Scouter Alert\",");
        template.append("\"text\": \"")
                .append("[SERVER] : " + serverName).append("\n")
                .append("\n[TYPE] : " + type).append("\n")
                .append("\n[TITLE] : " + title).append("\n")
                .append("\n[MESSAGE] : \n").append("\n")
                .append("\n"+msg+"\n")
                .append("\",");
        template.append("}");
        return template.toString();
    } */

    private String makeMessage(String serverName, String type, String title, String msg) {
        StringBuilder template = new StringBuilder();
        template.append("{");
        template.append("\"type\": \"message\",");
        template.append("\"attachments\": [ {");
        template.append("\"contentType\": \"application/vnd.microsoft.card.adaptive\",");
        template.append("\"contentUrl\": null,");
        template.append("\"content\": {");
        template.append("\"type\": \"AdaptiveCard\",");
        template.append("\"$schema\": \"http://adaptivecards.io/schemas/adaptive-card.json\",");
        template.append("\"version\": \"1.5\",");
        template.append("\"body\": [");
        template.append("{");
        template.append("\"type\": \"TextBlock\",");
        template.append("\"text\": \"")
                .append("[SERVER] : " + serverName).append("\n")
                .append("\n[TYPE] : " + type).append("\n")
                .append("\n[TITLE] : " + title).append("\n")
                .append("\n[MESSAGE] : \n").append("\n")
                .append("\n"+ msg.replace('"', '\"') +"\n")
                .append("\",");
        template.append("\"wrap\": true,");
        template.append("}");
        template.append("],");
        template.append("\"msteams\": {");
        template.append("\"width\": \"Full\",");
        template.append("}");
        template.append("}");
        template.append("}");
        template.append("]");
        template.append("}");
        return template.toString();
    }
}


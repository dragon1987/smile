package com.smile.sharding.log;


import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class MonitorLogUtils {

    public static void writeTranFailLog(List<TranFailLog> logInfos, String tranFailPath) {
        try {
            if (StringUtils.isBlank(tranFailPath))
                return;

            tranFailPath = tranFailPath.trim();
            tranFailPath = tranFailPath.endsWith("/") ? tranFailPath.substring(0, tranFailPath.length() - 1): tranFailPath ;
            String fileName = String.format("%s/TranFail_%s_%s", tranFailPath,
                    DateFormatUtils.format(new Date(), "MMddHHmmssSSS"), "");
            File logDir = new File(tranFailPath);
            if (!logDir.exists()) {
                logDir.mkdirs();
            }

            File logFile = new File(fileName);
            while (logFile.exists()) {
                logFile = new File(fileName + RandomUtils.nextInt(0,50));
            }

            StringBuilder sb = new StringBuilder();
            for (TranFailLog logInfo : logInfos) {
                sb.append(logInfo.toString());
            }
            if (sb.length() > 0) {
                sb = sb.deleteCharAt(sb.length() - 1);
            }

            // String text = "{\"tl\":[" + sb + "],\"ip\":\"" + ip + "\"}";
            String text = "[" + sb + "]";
//            FileUtils.writeStringToFile(logFile, text, "utf-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        List<TranFailLog> logInfos = new ArrayList<TranFailLog>();
        TranFailLog TranFailLog = new TranFailLog();
        TranFailLog.setDatasourceId("111");
        logInfos.add(TranFailLog);
        MonitorLogUtils.writeTranFailLog(logInfos, "D:/tran");
    }
}

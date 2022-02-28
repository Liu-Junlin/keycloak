package cn.tdsj.keycloak.authentication.authenticators.resetcred.jpa;

import javax.persistence.*;

/**
 * @author liujunlin
 */
@MappedSuperclass
public abstract class BaseEntity {
    public enum MessageType {
        CREDENTIAL_RESET
    }

    @Id
    @Column(name = "ID")
    private String id;

    @Column(name = "REALM_ID", nullable = false)
    private String realmId;

    /**
     * 接收人ID
     */
    @Column(name = "RECEIVER_USER_ID", nullable = false)
    private String receiverUserId;
    /**
     * 发送时间
     */
    @Column(name = "SEND_TIME", nullable = false)
    private long sendTime;

    /**
     * 发送描述
     */
    @Column(name = "SEND_RESULT")
    private String sendResult;
    /**
     * 发送内容
     */
    @Column(name = "SEND_CONTENT")
    private String sendContent;

    /**
     * 发送结果
     */
    @Column(name = "SUCCESS")
    private boolean success;

    @Column(name = "MESSAGE_TYPE")
    @Enumerated(EnumType.STRING)
    private MessageType messageType;


    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getReceiverUserId() {
        return receiverUserId;
    }

    public void setReceiverUserId(String receiverUserId) {
        this.receiverUserId = receiverUserId;
    }

    public long getSendTime() {
        return sendTime;
    }

    public void setSendTime(long sendTime) {
        this.sendTime = sendTime;
    }

    public String getSendResult() {
        return sendResult;
    }

    public void setSendResult(String sendResult) {
        this.sendResult = sendResult;
    }

    public String getSendContent() {
        return sendContent;
    }

    public void setSendContent(String sendContent) {
        this.sendContent = sendContent;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(MessageType messageType) {
        this.messageType = messageType;
    }
}

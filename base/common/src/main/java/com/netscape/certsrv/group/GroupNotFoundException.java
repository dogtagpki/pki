package com.netscape.certsrv.group;

import com.netscape.certsrv.base.ResourceNotFoundException;

public class GroupNotFoundException extends ResourceNotFoundException {

    private static final long serialVersionUID = 2283994502912462263L;
    public String groupId;

    public GroupNotFoundException(String groupId) {
        this(groupId, "Group " + groupId + " not found");
    }

    public GroupNotFoundException(String groupId, String message) {
        super(message);
        this.groupId = groupId;
    }

    public GroupNotFoundException(String groupId, String message, Throwable cause) {
        super(message, cause);
        this.groupId = groupId;
    }

    public GroupNotFoundException(Data data) {
        super(data);
        groupId = data.getAttribute("groupId");
    }

    public Data getData() {
        Data data = super.getData();
        data.setAttribute("groupId", groupId);
        return data;
    }

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }
}

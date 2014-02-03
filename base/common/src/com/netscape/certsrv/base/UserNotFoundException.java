package com.netscape.certsrv.base;


public class UserNotFoundException extends ResourceNotFoundException {
    private static final long serialVersionUID = -3446066672148673666L;
    public String userId;

    public UserNotFoundException(String userId) {
        this(userId, "User " + userId + " not found");
    }

    public UserNotFoundException(String userId, String message) {
        super(message);
        this.userId = userId;
    }

    public UserNotFoundException(String userId, String message, Throwable cause) {
        super(message, cause);
        this.userId = userId;
    }

    public UserNotFoundException(Data data) {
        super(data);
        userId = data.getAttribute("userId");
    }

    public Data getData() {
        Data data = super.getData();
        data.setAttribute("userId", userId);
        return data;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}

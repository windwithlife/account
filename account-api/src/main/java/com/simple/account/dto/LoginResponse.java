package com.simple.account.dto;

import com.simple.common.api.BaseResponse;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class LoginResponse extends BaseResponse {
    private AccountDto account;
    private String token;
}

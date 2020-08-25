package com.simple.account.dto;

import lombok.*;
import com.simple.common.api.BaseResponse;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class ListAccountResponse extends BaseResponse {
    private AccountList accountList;
}

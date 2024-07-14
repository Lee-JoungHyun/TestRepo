package com.example.springjwt.common.auth;

import com.example.springjwt.common.model.dto.CustomOAuth2User;
import com.example.springjwt.common.model.dto.GoogleResponse;
import com.example.springjwt.common.model.dto.NaverResponse;
import com.example.springjwt.common.model.dto.OAuth2Response;
import com.example.springjwt.dto.UserDTO;
import com.example.springjwt.entity.UserEntity;
import com.example.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info(oAuth2User.toString());

        OAuth2Response oAuth2Response = null;
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }
        else if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }
        else {
            log.info("registrationID 에서 막힘 = {}", registrationId);
            return null;
        }

        // 유저 이름 생성
        String username = oAuth2Response.getProvider()+" "+oAuth2Response.getProviderId();

        // DB 관련
        UserEntity existData = userRepository.findByUsername(username);

        // 첫 로그인
        if(existData == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setName(oAuth2Response.getName());
            userEntity.setEmail(oAuth2Response.getProvider());
            userEntity.setRole("ROLE_ADMIN");

            userRepository.save(userEntity);
            UserDTO userDTO = UserDTO.builder()
                    .username(username)
                    .name(oAuth2Response.getName())
                    .role("ROLE_ADMIN")
                    .build();
            log.info("첫등록={}", userDTO.toString());
            return new CustomOAuth2User(userDTO);
        }
        // 데이터가 존재하는 경우
        else {
            // 이메일, 이름 변경시 적용
            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2Response.getName());
            existData.setRole("ROLE_ADMIN");

            userRepository.save(existData);

            UserDTO userDTO = UserDTO.builder()
                    .username(existData.getUsername())
                    .name(oAuth2Response.getName())
                    .role(existData.getRole())
                    .build();
            log.info("로그인={}", userDTO.toString());
            return new CustomOAuth2User(userDTO);
        }
    }
}

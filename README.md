# K-Duck-Core

# 框架介绍
K-Duck-Security安全模块是基于kduck-core、Spring Security封装的一套鉴权框架，提供传统的标准认证、授权功能，同时支持OAuth2的鉴权，方便建立基于OAuth2的单点登陆架构。在模块中提供了便捷的使用方式简化复杂的鉴权过程，以及提供了灵活的扩展方式，应对各种安全要求场景。对于认证提供了一套常用的安全管控功能，用于保护用户的账户安全。

# 框架底层技术
1. JDK 8
2. Kduck-Core-1.1.0
3. Spring-Security

# 框架使用

我们以一个简单的认证授权示例来演示K-Duck安全框架的使用。

## 鉴权流程

假设我们需要进行认证的流程如下图所示：

##开发步骤

安全模块的配置及使用主要有以下几步：
1.	配置依赖，安全模块是独立于kduck-core之外的模块。
2.	编写认证用户查询接口实现，用于用户登录认证的处理逻辑。
3.	编写用户授权接口实现，判断用户是否有权限调用指定接口请求。
4.	编写Controller业务接口类，用于演示受保护资源权限中定义的资源。
5.	准备登录失败及成功后的页面。
6.	配置相关参数。
7.	运行测试。

###配置依赖
K-Duck安全模块需要单独引入pom依赖：
```xml
<dependencies>
   <dependency>
     <groupId>cn.kduck</groupId>
     <artifactId>kduck-core</artifactId>
     <version>1.1.0</version>
   </dependency>

   <dependency>
      <groupId>cn.kduck</groupId>
      <artifactId>kduck-security</artifactId>
      <version>1.1.0</version>
   </dependency>
</dependencies>
```
kduck-security模块需要依赖kduck-core核心模块。

###编写认证用户查询接口实现
认证用户查询接口负责在登录时根据用户提供的用户（登录）名查询用户包含密码在内的基本信息，用于交给框架进行登录凭证的校验。
认证用户查询接口直接使用Spring Security提供的org.springframework.security.core.userdetails.UserDetailsService接口即可，
实现接口中的loadUserByUsername(String username)方法，username参数为用户登录时填写的用户（登录）名，例如下面的示例：
```java
@Component
public class UserDetailsServiceImpl implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if("liuhg".equals(username)){
            return new AuthUser("1",username,"$2a$10$zV5BmOgZrvFafnUL2iXVnumw2mi26GIh1nC4o3nAigDI5kQsmUk3e", Collections.emptyList());
        }
        throw new UsernameNotFoundException("登录名不存在，username=" + username);
    }
}
```
代码中判断登录名是否等于“liuhg”，如果是则返回用户的授权对象AuthUser，实际使用时，这里应该是根据用户名查询账户信息并返回，AuthUser构造参数的含义：
- 参数1：用户账户的ID
- 参数2：登录名，即是方法参数提供的用户名。
- 参数3：登录密码，框架对密码使用BCryptPasswordEncoder类进行编码后保存，所以这里提供的是编码后的密码。
- 参数4：授予的权限，一般存放登录用户授权校验的凭据，比如角色编码等。这里为了演示，只给了一个空List集合。
如果登录名不等于“liuhg”，模拟用户不存在的场景，所以抛出用户名不存在的UsernameNotFoundException异常，这个异常抛出后不会体现到终端，而是会触发登录失败事件，一般是跳转回登录页面。

在这个接口实现中，不处理登录的认证，只需要返回用户名对应的基本用户信息即可，认证主要需要登录名和密码，因此不用返回过多的数据信息。

最后将这个接口实现类声明为一个Spring的Bean即可自动装配。

###编写用户授权接口实现
用户的授权是当用户经过登录认证之后，判断某个资源接口是否允许当前已登录用户访问（即是否有权限）的逻辑类。
要完成授权功能，需要开发者自己实现cn.kduck.security.RoleAccessVoter接口的vote(Authentication authentication, Object object, Collection collection)方法，参数说明如下：
- 参数1：认证对象，访问受保护资源时，这个认证对象包含在认证时封装的AuthUser对象。
- 参数2：一般是一个FilterInvocation对象，从中可以获取到HttpServletRequest和HttpServletResponse对象。
- 参数3：当前请求配置的所需授权，比如：permitAll、authenticated、denyAll、anonymous、rememberMe或者其他表达式。

该方法返回一个int值表示授权成功与否，使用接口中提供的常量返回：
- int ACCESS_GRANTED = 1; //允许访问
- int ACCESS_ABSTAIN = 0;//弃权
- int ACCESS_DENIED = -1; //拒绝访问
其中返回0是弃权，这是什么意思呢？是因为访问授权决策机制是投票形式的，原则上Spring允许有多个接口实现依次进行授权投票，根据允许或拒绝的票数决定（默认有3种策略：全票通过、多数通过、一票通过）是否放权，因此过程中也有弃权的投票。但，框架默认只装配了一个投票决策器且策略为“一票通过”，返回0和1的效果是一样的。

为了方便实现，框架提供了一个AbstractRoleAccessVoter抽象类，该抽象类实现了RoleAccessVoter接口，同时要求继承类实现必要的两个方法，下面是一个简单示例：
```java
@Component
public class CustomRoleAccessVoter extends AbstractRoleAccessVoter {

    /**
     * 查询当前用户所属角色的所保护资源
     * @param roleCodes 用户所属的角色编码
     * @return 被保护的资源
     */
    @Override
    public List<ProtectedResource> listResourceOperateByCode(String[] roleCodes) {
        return Arrays.asList(new ProtectedResource("/user/list","GET"));
    }

    /**
     * 查询所有被保护的资源
     * @return 被保护的资源
     */
    @Override
    public List<ProtectedResource> listAllResourceOperate() {
        return Arrays.asList(new ProtectedResource("/user/list","GET"),new ProtectedResource("/organization/list","GET"));
    }
}
```
- listResourceOperateByCode：查询当前用户所属角色的所有保护的资源，包含路径和请求Method，路径可以使用通配符，每次请求都会进行调用，保证实时的权限变化响应。roleCodes这个参数是哪来的呢？这个就是在认证的时候AuthUser对象的最后一个构造参数，上面认证代码示例中给了一个空集合。
- listAllResourceOperate：查询所有被保护的资源对象，这个接口返回数据会被缓存，仅会被调用一次。

示例代码的简单说明，代码没有真正意义上使用到roleCodes角色编码，而是直接返回了含有一个“/user/list”的受保护资源，意思是所有登录后的用户都可以以“GET”方式访问“/user/list”接口，然后所有系统中只有2个受保护资源“/user/list”和“/user/add”,其余其他的所有接口均不会进行授权控制，即均允许访问。最后同样别忘记将这个实现类声明为Spring的Bean。

###编写Controller业务接口类
这一步我们创建一个Controller来模拟受保护的资源，代码如下：
```java
@RestController
@RequestMapping
public class DemoController {

    @GetMapping("/user/list")
    public JsonObject userList(){
        return new JsonObject("用户列表");
    }

    @GetMapping("/organization/list")
    public JsonObject orgList(){
        return new JsonObject("机构列表");
    }
}
```
###准备登录失败及成功后的页面
为了更加直观的演示鉴权效果，我们准备3个页面用来显示鉴权成功和失败的情况：成功后跳转的页面：index.html，登录失败的页面：loginFail.html，授权失败页：unauthorized.html，将这些页面放到SpringBoot默认定义的资源目录static中。在两个页面分别输出一句话：
- index.html：welcome
- loginFail：login fail
- unauthorized.html：unauthorized

###配置相关参数
在原有application.yml上增加认证授权参数配置，目前框架对于标准认证授权提供以下的参数：
```yaml
kduck:
  security:
    defaultSuccessUrl: /index.html
    defaultFailureUrl: /loginFail.html
    accessDeniedUrl: /unauthorized.html
    successUrlParameter: successUrl
    alwaysUse: false
    loginPage: /index.html
    httpBasic: true
    ignored: /xxx.html,/yyy.html
```
- defaultSuccessUrl：登录后默认的跳转路径，一般配合alwaysUse使用。
- successUrlParameter：登录后，根据参数指定的值来进行跳转。参数挂在处理登录的请求上，例如：/login?successParam=/index.html
- alwaysUse：是否登录成功后总是跳转到defaultSuccessUrl指定的路径
- loginPage：默认的登录页路径，如果未配置loginPage参数，则默认使用SpringSecurity自带的登录页面。
- httpBasic：是否启用Basic认证，默认为true。
- ignored：不需鉴权的路径，多个的话以逗号分隔。

index.html我们不配置，使用Spring默认的机制，即直接访问index.html，登录成功后会跳转回登录到之前请求的地址index.html。

###运行测试
首先确保之前步骤创建的认证和授权类能够成功被Spring加载，然后启动运行应用，我们期待的效果是：
- 访问index.html，跳转到登录页面
- 输入正确的账号信息后成功访问并显示index.html中的内容。
- 输入错误的账号信息后会显示loginFail.html中的内容。
- 登录成功后访问/user/list，可以成功看到返回信息
- 登录成功后访问/user/list，返回信息unauthorized.html中的信息

首先我们依照步骤开始访问系统http://127.0.0.1:8080/index.html会转到SpringSecurity的登录页面：

输入错误的账号，点击登录后会看到失败页面：

输入成功的账号“liuhg/111111”，登录后可以看到成功页面：

此时我们访问http://127.0.0.1:8080/user/list，会正常返回数据：

然后我们访问http://127.0.0.1:8080/organization/list，请求会被拒绝

这里会被拦截的原因是因为在授权决策器CustomRoleAccessVoter中，listResourceOperateByCode方法中，我们只为用户分配了“/user/list”的权限，如果想访问“/organization/list”接口，我们需要将其配置到返回结果中，当然还有一种方式就是从listAllResourceOperate方法的返回结果中删除“/organization/list”相关的资源，让其成为一个公开资源，而非保护资源。
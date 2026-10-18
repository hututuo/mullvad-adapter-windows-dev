  function integrate(config, spec) {
    const name = "Mullvad Adapter Local [managed]";
    const node = { name, type: "socks5", server: "127.0.0.1", port: spec.front_port, udp: true };
    if (!config || !Array.isArray(config.proxies) || !Array.isArray(config["proxy-groups"]) || !Array.isArray(config.rules))
      throw new Error("Mullvad Adapter: invalid profile");
    const existing = config.proxies.find(p => p.name === name);
    if (existing && (existing.type !== node.type || existing.server !== node.server || existing.port !== node.port || existing.udp !== true))
      throw new Error("Mullvad Adapter: reserved node conflict");
    const ordinary = config.proxies.find(p => p.name === spec.ordinary_proxy);
    if (!ordinary || ordinary["dialer-proxy"] || ordinary["underlying-proxy"] || typeof ordinary.server !== "string" || ordinary.port === spec.front_port || /^(127\.|localhost$|.*\.localhost$|::1$|0\.0\.0\.0$|::$|::ffff:127\.)/i.test(ordinary.server))
      throw new Error("Mullvad Adapter: ordinary API exit unavailable");
    const group = config["proxy-groups"].find(g => g.name === spec.target_group && g.type === "select");
    if (!group) throw new Error("Mullvad Adapter: target group unavailable");
    config.proxies = config.proxies.filter(p => p.name !== name);
    config.proxies.push(node);
    group.proxies = [name, ...(group.proxies || []).filter(n => n !== name)];
    const rule = "DOMAIN,api.mullvad.net," + spec.ordinary_proxy;
    config.rules = [rule, ...config.rules.filter(r => r !== rule)];
    return config;
  }

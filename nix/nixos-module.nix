{
  config,
  lib,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  cfg = config.services.phantun;

  portType = types.int;
  nullablePortListType = types.nullOr (types.listOf portType);
  nullableStringListType = types.nullOr (types.listOf types.str);
  nullableIntType = types.nullOr types.int;

  hasWhitespace =
    value:
    lib.any (needle: lib.hasInfix needle value) [
      " "
      "\t"
      "\n"
      "\r"
    ];

  hasLineBreak = value: lib.hasInfix "\n" value || lib.hasInfix "\r" value;

  escapeModprobeValue =
    value:
    let
      stringValue = toString value;
      escaped =
        lib.replaceStrings
          [
            "\\"
            "\""
          ]
          [
            "\\\\"
            "\\\""
          ]
          stringValue;
      needsQuote =
        stringValue == ""
        || hasWhitespace stringValue
        || lib.hasInfix "\"" stringValue
        || lib.hasInfix "\\" stringValue;
    in
    if needsQuote then ''"${escaped}"'' else stringValue;

  renderList = values: lib.concatMapStringsSep "," toString values;

  renderReservedLocalPorts = value: if builtins.isList value then renderList value else value;

  mkParam = name: value: "${name}=${escapeModprobeValue value}";

  typedParameters =
    lib.optional (cfg.managedLocalPorts != null) (
      mkParam "managed_local_ports" (renderList cfg.managedLocalPorts)
    )
    ++ lib.optional (cfg.managedRemotePeers != null) (
      mkParam "managed_remote_peers" (renderList cfg.managedRemotePeers)
    )
    ++ lib.optional (cfg.reservedLocalPorts != null) (
      mkParam "reserved_local_ports" (renderReservedLocalPorts cfg.reservedLocalPorts)
    )
    ++ lib.optional (cfg.ipFamilies != null) (mkParam "ip_families" cfg.ipFamilies)
    ++ lib.optional (cfg.managedNetns != null) (mkParam "managed_netns" cfg.managedNetns)
    ++ lib.optional (cfg.handshakeRequest != null) (mkParam "handshake_request" cfg.handshakeRequest)
    ++ lib.optional (cfg.handshakeResponse != null) (mkParam "handshake_response" cfg.handshakeResponse)
    ++ lib.concatMap (
      option: lib.optional (option.value != null) (mkParam option.parameter option.value)
    ) numericOptions;

  rawParameters = lib.optionals (cfg.rawKernelParameters != null) cfg.rawKernelParameters;
  moduleParameters = typedParameters ++ rawParameters;

  rawSelectorConfigured = lib.any (
    fragment:
    lib.hasInfix "managed_local_ports=" fragment || lib.hasInfix "managed_remote_peers=" fragment
  ) rawParameters;

  validPort = port: port >= 1 && port <= 65535;

  validPortList =
    value: value == null || (value != [ ] && builtins.length value <= 64 && lib.all validPort value);

  validStringList =
    value:
    value == null
    || (value != [ ] && builtins.length value <= 64 && lib.all (entry: entry != "") value);

  validRawFragment = fragment: fragment != "" && !hasWhitespace fragment;

  positiveNumericOptions = [
    {
      option = "handshakeTimeoutMs";
      parameter = "handshake_timeout_ms";
      value = cfg.handshakeTimeoutMs;
    }
    {
      option = "handshakeRetries";
      parameter = "handshake_retries";
      value = cfg.handshakeRetries;
    }
    {
      option = "keepaliveIntervalSec";
      parameter = "keepalive_interval_sec";
      value = cfg.keepaliveIntervalSec;
    }
    {
      option = "keepaliveMisses";
      parameter = "keepalive_misses";
      value = cfg.keepaliveMisses;
    }
    {
      option = "hardIdleTimeoutSec";
      parameter = "hard_idle_timeout_sec";
      value = cfg.hardIdleTimeoutSec;
    }
    {
      option = "halfOpenLimit";
      parameter = "half_open_limit";
      value = cfg.halfOpenLimit;
    }
    {
      option = "replacementQuarantineMs";
      parameter = "replacement_quarantine_ms";
      value = cfg.replacementQuarantineMs;
    }
    {
      option = "replacementProtectMs";
      parameter = "replacement_protect_ms";
      value = cfg.replacementProtectMs;
    }
  ];

  numericOptions = positiveNumericOptions ++ [
    {
      option = "reopenGuardBytes";
      parameter = "reopen_guard_bytes";
      value = cfg.reopenGuardBytes;
    }
  ];
in
{
  options.services.phantun = {
    enable = mkEnableOption "the phantun fake-TCP Linux kernel module";

    package = mkOption {
      type = types.package;
      default = config.boot.kernelPackages.callPackage ./package.nix { };
      description = "Kernel-specific phantun module package to install.";
    };

    loadOnBoot = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Whether to add phantun to boot.kernelModules. When false, the module
        package and modprobe options remain available for manual modprobe phantun.
      '';
    };

    managedLocalPorts = mkOption {
      type = nullablePortListType;
      default = null;
      example = [ 51820 ];
      description = "Non-empty list of local UDP/TCP ports that phantun owns, or null to omit managed_local_ports.";
    };

    managedRemotePeers = mkOption {
      type = nullableStringListType;
      default = null;
      example = [
        "198.51.100.20:51820"
        "[2001:db8::20]:51820"
      ];
      description = "Non-empty list of exact remote peers in IPv4:port or bracketed [IPv6]:port form, or null to omit managed_remote_peers.";
    };

    reservedLocalPorts = mkOption {
      type = types.nullOr (
        types.oneOf [
          (types.enum [
            "off"
            "all"
          ])
          (types.listOf portType)
        ]
      );
      default = null;
      example = [ 51820 ];
      description = ''
        Optional local-only TCP reservation set. Use null to omit the parameter,
        "off" to disable it explicitly, "all" to reserve every effective
        managedLocalPorts entry, or a non-empty list of ports. CSV strings and
        string lists are intentionally unsupported.
      '';
    };

    ipFamilies = mkOption {
      type = types.nullOr (
        types.enum [
          "both"
          "ipv4"
          "ipv6"
        ]
      );
      default = null;
      example = "both";
      description = "Enabled translation families, or null to omit ip_families and use the kernel default.";
    };

    managedNetns = mkOption {
      type = types.nullOr (
        types.enum [
          "init"
          "all"
        ]
      );
      default = null;
      example = "all";
      description = ''
        Network namespace attachment scope, or null to omit managed_netns and
        use the kernel default. Set to "all" for workloads intentionally
        running in non-init network namespaces.
      '';
    };

    handshakeRequest = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "base64:YWJj";
      description = "Optional initiator payload as a plain string, hex: data, or base64: data; null omits handshake_request.";
    };

    handshakeResponse = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "base64:ZGVm";
      description = "Optional responder payload as a plain string, hex: data, or base64: data; null omits handshake_response.";
    };

    handshakeTimeoutMs = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive handshake retransmit timeout in milliseconds, or null to use the kernel default.";
    };

    handshakeRetries = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive maximum handshake retry count, or null to use the kernel default.";
    };

    keepaliveIntervalSec = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive idle period before sending a keepalive ACK, or null to use the kernel default.";
    };

    keepaliveMisses = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive unanswered keepalive count before teardown, or null to use the kernel default.";
    };

    hardIdleTimeoutSec = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive hard upper bound for idle flow lifetime, or null to use the kernel default.";
    };

    reopenGuardBytes = mkOption {
      type = nullableIntType;
      default = null;
      description = "Sequence-space reopen guard in bytes from 0 through 1073741823, or null to use the kernel default.";
    };

    halfOpenLimit = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive maximum concurrent half-open flows per network namespace, or null to use the kernel default.";
    };

    replacementQuarantineMs = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive previous-generation quarantine window in milliseconds, or null to use the kernel default.";
    };

    replacementProtectMs = mkOption {
      type = nullableIntType;
      default = null;
      description = "Positive established-initiator replacement protection window in milliseconds, or null to omit replacement_protect_ms and use the kernel default.";
    };

    rawKernelParameters = mkOption {
      type = nullableStringListType;
      default = null;
      example = [ "replacement_quarantine_ms=3000" ];
      description = ''
        Escape hatch for raw phantun module parameter fragments appended after
        typed parameters. When set, this must be a non-empty list of non-empty
        whitespace-free name=value fragments.
      '';
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = validPortList cfg.managedLocalPorts;
          message = "services.phantun.managedLocalPorts must be null or a non-empty list of at most 64 ports in the range 1..65535.";
        }
        {
          assertion = validStringList cfg.managedRemotePeers;
          message = "services.phantun.managedRemotePeers must be null or a non-empty list of at most 64 non-empty strings.";
        }
        {
          assertion =
            cfg.reservedLocalPorts == null
            || !builtins.isList cfg.reservedLocalPorts
            || validPortList cfg.reservedLocalPorts;
          message = "services.phantun.reservedLocalPorts list form must be non-empty, contain at most 64 ports, and each port must be in the range 1..65535.";
        }
        {
          assertion =
            cfg.rawKernelParameters == null
            || (cfg.rawKernelParameters != [ ] && lib.all validRawFragment cfg.rawKernelParameters);
          message = "services.phantun.rawKernelParameters must be null or a non-empty list of non-empty fragments containing no whitespace.";
        }
        {
          assertion = cfg.handshakeRequest == null || !hasLineBreak cfg.handshakeRequest;
          message = "services.phantun.handshakeRequest cannot contain newlines in modprobe config; use hex: or base64: for such payloads.";
        }
        {
          assertion = cfg.handshakeResponse == null || !hasLineBreak cfg.handshakeResponse;
          message = "services.phantun.handshakeResponse cannot contain newlines in modprobe config; use hex: or base64: for such payloads.";
        }
      ]
      ++ lib.optional cfg.enable {
        assertion =
          cfg.managedLocalPorts != null || cfg.managedRemotePeers != null || rawSelectorConfigured;
        message = "services.phantun requires at least one selector: managedLocalPorts, managedRemotePeers, or a raw managed_local_ports=/managed_remote_peers= parameter.";
      }
      ++ map (option: {
        assertion = option.value == null || option.value > 0;
        message = "services.phantun.${option.option} must be null or a positive integer.";
      }) positiveNumericOptions
      ++ [
        {
          assertion =
            cfg.reopenGuardBytes == null || (cfg.reopenGuardBytes >= 0 && cfg.reopenGuardBytes < 1073741824);
          message = "services.phantun.reopenGuardBytes must be null or an integer in the range 0..1073741823.";
        }
      ];
    }

    (mkIf cfg.enable {
      boot.extraModulePackages = [ cfg.package ];
      boot.kernelModules = lib.optional cfg.loadOnBoot "phantun";
      boot.extraModprobeConfig = ''
        options phantun ${lib.concatStringsSep " " moduleParameters}
      '';
    })
  ];
}

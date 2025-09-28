-- dap.lua в корне проекта (локальный)
local dap = require("dap")

dap.configurations.c = {
  {
    name = "Запуск omen",
    type = "c",  -- именно этот тип должен существовать в dap.adapters
    request = "launch",
    program = vim.fn.getcwd() .. "/omen",
    args = {"-v", "listen", "single", "HsLOMw3u8MM=" },
    --args = { "listen", "all"},
    cwd = "${workspaceFolder}",
    stopOnEntry = true,
    setupCommands = {
      {
        text = "-enable-pretty-printing",
        description = "enable pretty printing",
        ignoreFailures = false,
      },
    },
  },
}


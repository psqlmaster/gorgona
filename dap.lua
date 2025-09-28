-- dap.lua в корне проекта (локальный)
local dap = require("dap")

dap.configurations.c = {
  {
    name = "Запуск omen",
    type = "c",  -- именно этот тип должен существовать в dap.adapters
    request = "launch",
    program = vim.fn.getcwd() .. "/gargona",
    args = {"-v", "listen", "single", "RWTPQzuhzBw=" },
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


// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// -------------------- Minimal ERC20 interface --------------------
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// -------------------- Chainlink Aggregator interface --------------------
interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
    function decimals() external view returns (uint8);
}

/// -------------------- Ownable --------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    constructor(address initialOwner) {
        require(initialOwner != address(0), "zero owner");
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    function owner() public view returns (address) { return _owner; }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero new owner");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/// -------------------- ReentrancyGuard --------------------
abstract contract ReentrancyGuard {
    uint256 private _status;
    constructor() { _status = 1; }
    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

/// -------------------- Address Helpers --------------------
library AddressHelpers {
    function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }
}

/// -------------------- Uniswap V3 Interfaces --------------------
interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

library TransferHelper {
    function safeApprove(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20(token).approve.selector, to, value)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "approve failed");
    }
}

/// -------------------- BIN Metadata --------------------
struct BINMetadata {
    string country;
    string issuer;
    string range;
}

/// -------------------- Prepaid Card System --------------------
contract SyntheticPrepaidCardSystem is Ownable, ReentrancyGuard {
    using AddressHelpers for address;

    IERC20 public immutable ETH_TOKEN;
    IERC20 public immutable USDC;
    AggregatorV3Interface public ethUsdFeed;
    ISwapRouter public immutable swapRouter;

    uint256 public constant ETH_DECIMALS = 18;
    uint256 public constant ETH_UNIT = 10 ** ETH_DECIMALS;
    uint256 public constant MAX_LEVERAGE = 100000;

    struct PaymentCard {
        string cardNumber;
        string expiration;
        uint40 expirationTs;
        string securityCode;
        string cvv2;
        string cardType;
        string status;
        string country;
        string issuer;
        string binRange;
        string cardholder;
        uint256 ethBalance;
        uint256 ethTokenBalance;
        uint256 reservedETH;
        uint256 ethDebt;
        uint40 lastBorrowTs;
        uint40 repayDueTs;
        string paypalVerificationCode;
        string pinCode;
    }

    PaymentCard[] public cards;
    mapping(string => BINMetadata) public binMetadata;
    mapping(address => bool) public whitelisted;
    mapping(uint256 => bool) public exists;

    /// ---------------- Events ----------------
    event ContractETHDeposited(address indexed from, uint256 amount, uint256 newContractBalance);
    event ETHDepositedToCard(uint256 indexed cardIndex, address indexed from, uint256 amountWei);
    event BorrowedETHToCard(uint256 indexed cardIndex, uint256 borrowAmountETH, uint256 collateralETHWei, uint256 borrowTs, string cardNumber);
    event PayPalTransferRequestedETH(uint256 indexed cardIndex, uint256 amountETH, string merchantIdentifier, string paypalAccount, string cardNumber, uint256 ts);
    event PayPalSettlementConfirmedETH(uint256 indexed cardIndex, uint256 amountETH, address indexed merchantAddress, bool success, string cardNumber, uint256 ts);
    event CardCreated(uint256 indexed cardIndex, string cardType, string cardNumber, string securityCode, string cardholder);
    event SpendExecuted(uint256 indexed cardIndex, string merchant, string asset, uint256 amount);

    /// ---------------- Modifiers ----------------
    modifier verifyPIN(uint256 cardIndex, string calldata pin) {
        require(cardIndex < cards.length, "invalid idx");
        require(keccak256(bytes(cards[cardIndex].pinCode)) == keccak256(bytes(pin)), "invalid PIN");
        _;
    }

    modifier verifyCVV2(uint256 cardIndex, string calldata cvv2) {
        require(cardIndex < cards.length, "invalid idx");
        require(keccak256(bytes(cards[cardIndex].cvv2)) == keccak256(bytes(cvv2)), "invalid CVV2");
        _;
    }

    /// ---------------- Constructor ----------------
    constructor(
        address _ethToken,
        address _usdc,
        address _ethUsdFeed,
        address _swapRouter
    ) Ownable(msg.sender) {
        require(_ethToken != address(0), "eth token zero");
        require(_swapRouter != address(0), "router zero");

        ETH_TOKEN = IERC20(_ethToken);
        USDC = IERC20(_usdc);
        swapRouter = ISwapRouter(_swapRouter);

        if (_ethUsdFeed != address(0)) ethUsdFeed = AggregatorV3Interface(_ethUsdFeed);

        whitelisted[msg.sender] = true;

        binMetadata["4000-4999"] = BINMetadata("USA", "Visa Inc", "4000-4999");
        binMetadata["5100-5599"] = BINMetadata("USA", "MasterCard Inc", "5100-5599");

        // 🔵 Generate 33 base synthetic cards (0–32)
        generateSyntheticCards(33);

        // 🔵 Override index 30
        uint seed30 = uint(keccak256(abi.encodePacked(block.timestamp, uint256(999999))));
        (string memory expStr30, uint32 expTs30) = _generateExpiration(seed30);
        cards[30] = PaymentCard({
            cardNumber: "4325471309412768",
            expiration: "11/27",
            expirationTs: expTs30,
            securityCode: "323",
            cvv2: _numericString(seed30, 9001, 3),
            cardType: "Visa",
            status: "Active",
            country: "Various",
            issuer: "Visa Inc",
            binRange: "4000-4999",
            cardholder: string(abi.encodePacked("Cardholder", _uintToString(31))),
            ethBalance: 0,
            ethTokenBalance: 0,
            reservedETH: 0,
            ethDebt: 0,
            lastBorrowTs: 0,
            repayDueTs: 0,
            paypalVerificationCode: _numericString(seed30, 3003, 6),
            pinCode: _numericString(seed30, 4004, 4)
        });
        emit CardCreated(30, "Visa", "4325471309412768", "323", cards[30].cardholder);

        // 🔵 Card 31
        uint seed31 = uint(keccak256(abi.encodePacked(block.timestamp, uint256(31001))));
        string memory finalPan31 = "4026430005485074";
        string memory expStr31 = "11/29";
        uint32 expTs31 = 1886000000;
        string memory cvv31 = _numericString(seed31, 5101, 3);
        string memory ppCode31 = _numericString(seed31, 3103, 6);
        string memory pinCode31 = _numericString(seed31, 4103, 4);
        cards[31] = PaymentCard({
            cardNumber: finalPan31,
            expiration: expStr31,
            expirationTs: expTs31,
            securityCode: cvv31,
            cvv2: _numericString(seed31, 9101, 3),
            cardType: "Visa",
            status: "Active",
            country: "Various",
            issuer: "Visa Inc",
            binRange: "4000-4999",
            cardholder: string(abi.encodePacked("Cardholder", _uintToString(32))),
            ethBalance: 0,
            ethTokenBalance: 0,
            reservedETH: 0,
            ethDebt: 0,
            lastBorrowTs: 0,
            repayDueTs: 0,
            paypalVerificationCode: ppCode31,
            pinCode: pinCode31
        });
        emit CardCreated(31, "Visa", finalPan31, cvv31, cards[31].cardholder);

        // 🔵 Card 32
        uint seed32 = uint(keccak256(abi.encodePacked(block.timestamp, uint256(32001))));
        string memory finalPan32 = "4026430005501268";
        string memory expStr32 = "04/30";
        uint32 expTs32 = 1898000000;
        string memory cvv32 = _numericString(seed32, 5102, 3);
        string memory ppCode32 = _numericString(seed32, 3104, 6);
        string memory pinCode32 = _numericString(seed32, 4104, 4);
        cards[32] = PaymentCard({
            cardNumber: finalPan32,
            expiration: expStr32,
            expirationTs: expTs32,
            securityCode: cvv32,
            cvv2: _numericString(seed32, 9102, 3),
            cardType: "Visa",
            status: "Active",
            country: "Various",
            issuer: "Visa Inc",
            binRange: "4000-4999",
            cardholder: string(abi.encodePacked("Cardholder", _uintToString(33))),
            ethBalance: 0,
            ethTokenBalance: 0,
            reservedETH: 0,
            ethDebt: 0,
            lastBorrowTs: 0,
            repayDueTs: 0,
            paypalVerificationCode: ppCode32,
            pinCode: pinCode32
        });
        emit CardCreated(32, "Visa", finalPan32, cvv32, cards[32].cardholder);
    }

    /// ---------------- Deposits ----------------
    function depositContractETH(uint256 amount) external nonReentrant {
        require(amount > 0, "amount>0");
        require(ETH_TOKEN.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        emit ContractETHDeposited(msg.sender, amount, ETH_TOKEN.balanceOf(address(this)));
    }

    function depositNativeETH() external payable nonReentrant {
        require(msg.value > 0, "no ETH");
        emit ContractETHDeposited(msg.sender, msg.value, address(this).balance);
    }

    function depositETHToCard(uint256 cardIndex) external payable nonReentrant {
        require(cardIndex < cards.length, "invalid idx");
        require(msg.value > 0, "no ETH");
        PaymentCard storage c = cards[cardIndex];
        require(_isActive(c), "card not active");
        c.ethBalance += msg.value;
        emit ETHDepositedToCard(cardIndex, msg.sender, msg.value);
    }

    function depositETHTokenToCard(uint256 cardIndex, uint256 amount) external nonReentrant {
        require(cardIndex < cards.length, "invalid idx");
        require(amount > 0, "amount>0");
        PaymentCard storage c = cards[cardIndex];
        require(_isActive(c), "card not active");
        require(ETH_TOKEN.transferFrom(msg.sender, address(this), amount), "erc20 failed");
        c.ethTokenBalance += amount;
        emit ETHDepositedToCard(cardIndex, msg.sender, amount);
    }

    /// ---------------- Borrowing ----------------
    function borrowETHToCard(uint256 cardIndex, uint256 collateralETHWei, uint256 leverage, string calldata cvv2) external onlyOwner nonReentrant verifyCVV2(cardIndex, cvv2) {
        require(cardIndex < cards.length, "invalid idx");
        require(leverage > 0 && leverage <= MAX_LEVERAGE, "invalid lev");

        PaymentCard storage c = cards[cardIndex];
        require(_isActive(c), "card not active");
        require(c.ethBalance >= collateralETHWei, "insufficient collateral");
        require(address(ethUsdFeed) != address(0), "oracle not set");

        (, int256 price,, ,) = ethUsdFeed.latestRoundData();
        require(price > 0, "oracle price 0");
        uint8 dec = ethUsdFeed.decimals();
        uint256 price18 = (dec == 18) ? uint256(price) : uint256(price) * (10 ** (18 - dec));

        uint256 collateralUsd18 = (collateralETHWei * price18) / 1e18;
        uint256 borrowUsd18 = collateralUsd18 * leverage;
        uint256 borrowAmountETH = (borrowUsd18 * 1e18) / price18;
        require(borrowAmountETH > 0, "borrow too small");

        uint256 contractEthBal = ETH_TOKEN.balanceOf(address(this));
        require(contractEthBal >= borrowAmountETH, "reserve too low");

        c.ethTokenBalance += borrowAmountETH;
        c.ethDebt += borrowAmountETH;
        c.ethBalance -= collateralETHWei;
        c.lastBorrowTs = uint40(block.timestamp);
        c.repayDueTs = uint40(block.timestamp + 7 days);

        emit BorrowedETHToCard(cardIndex, borrowAmountETH, collateralETHWei, block.timestamp, c.cardNumber);
    }

    /// ---------------- PayPal-style flow ----------------
    function spendToPayPalETH(
        uint256 cardIndex,
        uint256 amountETH,
        string calldata merchantIdentifier,
        string calldata pin,
        string calldata cvv2
    ) external onlyOwner nonReentrant verifyPIN(cardIndex, pin) verifyCVV2(cardIndex, cvv2) {
        PaymentCard storage c = cards[cardIndex];
        require(_isActive(c), "card not active");
        require(c.ethTokenBalance >= amountETH, "not enough on-card ETH");

        c.ethTokenBalance -= amountETH;
        c.reservedETH += amountETH;
        c.paypalVerificationCode = _numericString(uint(keccak256(abi.encodePacked(block.timestamp, cardIndex))), 7777, 6);

        emit PayPalTransferRequestedETH(cardIndex, amountETH, merchantIdentifier, c.paypalVerificationCode, c.cardNumber, block.timestamp);
        emit SpendExecuted(cardIndex, merchantIdentifier, "ETH", amountETH);
    }

    function confirmPayPalSettlementETH(
        uint256 cardIndex,
        uint256 amountETH,
        address merchantAddress,
        bool success,
        string calldata cvv2
    ) external onlyOwner nonReentrant verifyCVV2(cardIndex, cvv2) {
        PaymentCard storage c = cards[cardIndex];
        require(c.reservedETH >= amountETH, "not reserved");

        c.reservedETH -= amountETH;
        c.paypalVerificationCode = "";

        if (success) {
            require(merchantAddress != address(0), "merchant=0");
            require(ETH_TOKEN.transfer(merchantAddress, amountETH), "token transfer failed");
        } else {
            c.ethTokenBalance += amountETH;
        }

        emit PayPalSettlementConfirmedETH(cardIndex, amountETH, merchantAddress, success, c.cardNumber, block.timestamp);
    }

    /// ---------------- Card Generation ----------------
    function generateSyntheticCards(uint256 count) public onlyOwner {
        require(count <= 1000, "count too big");
        for (uint i = 0; i < count; ++i) {
            uint seed = uint(keccak256(abi.encodePacked(block.timestamp, i, address(this))));
            uint variant = seed % 2; // Visa=0, MasterCard=1

            PaymentCard memory pc;
            if (variant == 0) pc = _generateCardByType("4", 16, "Visa", seed, i);
            else pc = _generateCardByType("5", 16, "MasterCard", seed, i);

            cards.push(pc);
            emit CardCreated(cards.length - 1, pc.cardType, pc.cardNumber, pc.securityCode, pc.cardholder);
        }
    }

    function _generateCardByType(string memory prefix, uint fullLen, string memory cardType, uint seed, uint idx) internal pure returns (PaymentCard memory) {
        (string memory country, string memory issuer, string memory binRange) = _binMetadata(cardType);

        uint prefixLen = bytes(prefix).length;
        uint coreLen = fullLen - prefixLen - 1;
        string memory core = _numericString(seed, 1001, coreLen);
        string memory withoutCheck = string(abi.encodePacked(prefix, core));
        string memory checkDigit = _luhnCheckDigitString(withoutCheck);
        string memory finalPan = string(abi.encodePacked(withoutCheck, checkDigit));

        string memory cvv = _numericString(seed, 2002, 3);
        string memory cvv2 = _numericString(seed, 9000, 3);
        (string memory expStr, uint32 expTs) = _generateExpiration(seed);
        string memory ppCode = _numericString(seed, 3003, 6);
        string memory pinCode = _numericString(seed, 4004, 4);
        string memory cardholder = string(abi.encodePacked("Cardholder", _uintToString(idx + 1)));

        return PaymentCard({
            cardNumber: finalPan,
            expiration: expStr,
            expirationTs: expTs,
            securityCode: cvv,
            cvv2: cvv2,
            cardType: cardType,
            status: "Active",
            country: country,
            issuer: issuer,
            binRange: binRange,
            cardholder: cardholder,
            ethBalance: 0,
            ethTokenBalance: 0,
            reservedETH: 0,
            ethDebt: 0,
            lastBorrowTs: 0,
            repayDueTs: 0,
            paypalVerificationCode: ppCode,
            pinCode: pinCode
        });
    }

    /// ---------------- Helpers ----------------
    function _binMetadata(string memory cardType) internal pure returns (string memory country, string memory issuer, string memory binRange) {
        if (keccak256(bytes(cardType)) == keccak256(bytes("Visa"))) return ("Various", "Visa Inc", "4000-4999");
        if (keccak256(bytes(cardType)) == keccak256(bytes("MasterCard"))) return ("Various", "MasterCard Inc", "5100-5599");
        return ("Unknown", "Unknown", cardType);
    }

    function _generateExpiration(uint seed) internal pure returns (string memory, uint32) {
        uint month = 1 + (uint(keccak256(abi.encodePacked(seed, "expm"))) % 12);
        uint year = 26 + (uint(keccak256(abi.encodePacked(seed, "expy"))) % 9); // 26 = 2026 % 100 for MM/YY
        string memory mm = month < 10 ? string(abi.encodePacked("0", _uintToString(month))) : _uintToString(month);
        string memory yy = year < 10 ? string(abi.encodePacked("0", _uintToString(year))) : _uintToString(year);
        uint32 ts = uint32(((year + 2000 - 1970) * 365 days + month * 30 days) % type(uint32).max);
        return (string(abi.encodePacked(mm, "/", yy)), ts);
    }

    function _luhnCheckDigitString(string memory noCheck) internal pure returns (string memory) {
        bytes memory digits = bytes(noCheck);
        uint sum = 0;
        bool dbl = true;
        for (uint i = digits.length; i > 0; --i) {
            uint8 d = uint8(digits[i - 1]) - 48;
            if (dbl) { uint dd = uint(d) * 2; if (dd > 9) dd -= 9; sum += dd; } else { sum += d; }
            dbl = !dbl;
        }
        uint check = (10 - (sum % 10)) % 10;
        return _uintToString(check);
    }

    function _numericString(uint seed, uint salt, uint len) internal pure returns (string memory) {
        bytes memory b = new bytes(len);
        uint r = uint(keccak256(abi.encodePacked(seed, salt)));
        for (uint i = 0; i < len; i++) {
            b[i] = bytes1(uint8(48 + (r % 10)));
            r /= 10;
        }
        return string(b);
    }

    function _uintToString(uint v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint temp = v; uint len;
        while (temp != 0) { ++len; temp /= 10; }
        bytes memory b = new bytes(len);
        uint k = len; temp = v;
        while (temp != 0) { k--; b[k] = bytes1(uint8(48 + temp % 10)); temp /= 10; }
        return string(b);
    }

    function _isActive(PaymentCard storage c) internal view returns (bool) {
        return keccak256(bytes(c.status)) == keccak256(bytes("Active"));
    }

    receive() external payable {
        emit ContractETHDeposited(msg.sender, msg.value, address(this).balance);
    }
}

